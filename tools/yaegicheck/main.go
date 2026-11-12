// Command yaegicheck loads the plugin with the Yaegi interpreter and the symbol
// table used by Traefik, then serves a request through the middleware.
//
// It is a regression guard for interpreter incompatibilities: Yaegi pins down
// what the plugin sources may contain (see the README), and a construct
// accepted by the Go compiler can crash the interpreter while Traefik loads the
// plugin. Run it before every release:
//
//	make yaegi-check
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

const moduleRoot = "github.com/MichNG/traefik-keycloak-auth"
const pluginImport = moduleRoot

func main() {
	root, err := repoRoot()
	if err != nil {
		fail("locating the repository root: %v", err)
	}

	gopath, err := os.MkdirTemp("", "yaegicheck-gopath")
	if err != nil {
		fail("creating the temporary GOPATH: %v", err)
	}
	defer func() { _ = os.RemoveAll(gopath) }()

	if err := os.Setenv("GOPATH", gopath); err != nil {
		fail("setting GOPATH: %v", err)
	}

	src := filepath.Join(gopath, "src", moduleRoot)
	if err := copyTree(root, src); err != nil {
		fail("copying the plugin sources: %v", err)
	}

	i := interp.New(interp.Options{GoPath: gopath, Env: os.Environ(), Stdout: os.Stdout, Stderr: os.Stderr})
	if err := i.Use(stdlib.Symbols); err != nil {
		fail("loading the stdlib symbols: %v", err)
	}

	fmt.Println("=== compiling the plugin with yaegi ===")
	if _, err := i.Eval(fmt.Sprintf("import %q", pluginImport)); err != nil {
		fail("the plugin does not compile under yaegi: %v", err)
	}

	newFn, err := i.Eval("traefik_keycloak_auth.New")
	if err != nil {
		fail("looking up New: %v", err)
	}

	checkConfigurationErrors(i, newFn)
	checkClaims(i)
	checkRequest(i, newFn)

	fmt.Println("OK: the plugin compiles and runs under yaegi")
}

// checkClaims evaluates the Hub claims expression under yaegi against a nested
// claim (a Keycloak `realm_access.roles`), the case that matters in practice.
func checkClaims(i *interp.Interpreter) {
	fmt.Println("=== claims expression evaluated by the interpreter ===")

	if _, err := i.Eval(fmt.Sprintf("import %q", moduleRoot+"/internal/claims")); err != nil {
		fail("importing the claims package: %v", err)
	}
	if _, err := i.Eval(`import "encoding/json"`); err != nil {
		fail("importing encoding/json: %v", err)
	}

	// Build the claims the way the middleware does: decoded by encoding/json.
	// The two tokens carry DIFFERENT values on purpose, so that a mix-up
	// between the ID token and the access token paths is caught.
	if _, err := i.Eval("idat := map[string]interface{}{}\n" +
		"json.Unmarshal([]byte(`{\"grp\":\"id-admin\",\"email\":\"id@example.com\"}`), &idat)\n" +
		"accat := map[string]interface{}{}\n" +
		"json.Unmarshal([]byte(`{\"grp\":\"access-admin\",\"scope\":\"openid profile writer\",\"realm_access\":{\"roles\":[\"admin\",\"user\"]}}`), &accat)\n" +
		"v := claims.Values{IDToken: idat, AccessToken: accat}"); err != nil {
		fail("building the claims values: %v", err)
	}

	cases := []struct {
		expr string
		want bool
	}{
		{"Equals(`grp`, `id-admin`)", true},
		{"Equals(`id_token.grp`, `id-admin`)", true},
		{"Equals(`id_token.grp`, `access-admin`)", false},
		{"Equals(`access_token.grp`, `access-admin`)", true},
		{"Equals(`access_token.grp`, `id-admin`)", false},
		{"Equals(`access_token.scope`, `openid profile writer`)", true},
		{"Prefix(`access_token.scope`, `openid`)", true},
		{"Prefix(`access_token.scope`, `nope`)", false},
		{"SplitContains(`access_token.scope`, ` `, `writer`)", true},
		{"SplitContains(`access_token.scope`, ` `, `reader`)", false},
		{"Contains(`access_token.scope`, `writer`)", true},
		{"Contains(`access_token.scope`, `nope`)", false},
		{"Equals(`realm_access.roles`, `admin`)", false},
		{"OneOf(`access_token.realm_access.roles`, `admin`)", true},
		{"OneOf(`access_token.realm_access.roles`, `reader`)", false},
		{"Equals(`access_token.realm_access.roles`, `admin`) && !OneOf(`access_token.realm_access.roles`, `reader`)", true},
		// The single-character OR operand is documented too.
		{"Equals(`access_token.grp`, `access-admin`) | Equals(`access_token.grp`, `id-admin`)", true},
	}

	for index, tc := range cases {
		if _, err := i.Eval(fmt.Sprintf("e%d, err%d := claims.Parse(%q)", index, index, tc.expr)); err != nil {
			fail("parsing %q: %v", tc.expr, err)
		}
		result, err := i.Eval(fmt.Sprintf("e%d.Eval(v)", index))
		if err != nil {
			fail("evaluating %q: %v", tc.expr, err)
		}
		if got := boolValue(result.Interface()); got != tc.want {
			fail("%q -> %v under yaegi, want %v", tc.expr, got, tc.want)
		}
	}

	fmt.Println("OK: the claims expression behaves correctly under yaegi")

	// Same as above, but the parsed expression is stored in a struct field of
	// another package and evaluated from there - exactly how the middleware
	// keeps it (config.AuthorizationConfig.Expr).
	if _, err := i.Eval(fmt.Sprintf("import %q", moduleRoot+"/internal/config")); err != nil {
		fail("importing the config package: %v", err)
	}
	if _, err := i.Eval(`authz := &config.AuthorizationConfig{}`); err != nil {
		fail("allocating the authorization config: %v", err)
	}
	if _, err := i.Eval("authz.Expr, _ = claims.Parse(\"OneOf(`access_token.realm_access.roles`, `admin`)\")"); err != nil {
		fail("parsing into the config field: %v", err)
	}
	result, err := i.Eval(`authz.Expr.Eval(v)`)
	if err != nil {
		fail("evaluating from the config field: %v", err)
	}
	if !boolValue(result.Interface()) {
		fail("the expression stored in a config field evaluates to false")
	}
	fmt.Println("OK: the expression stored across packages still evaluates correctly")
}

// boolValue unwraps the *interface{} yaegi returns for a boolean expression.
func boolValue(raw interface{}) bool {
	if ptr, ok := raw.(*interface{}); ok {
		raw = *ptr
	}
	value, _ := raw.(bool)
	return value
}

// checkRequest builds a valid configuration and drives one request through the
// middleware. The issuer points at a closed port, so the discovery fails with
// a 500: what matters is that no panic escapes and the failure is reported.
func checkRequest(i *interp.Interpreter, newFn reflect.Value) {
	fmt.Println("=== serving a request (issuer unreachable) ===")

	cfg := createConfig(i, func(value reflect.Value) {
		value.FieldByName("Issuer").SetString("http://127.0.0.1:1/realms/myrealm")
		value.FieldByName("RedirectURL").SetString("/callback")
		value.FieldByName("ClientID").SetString("traefik")
		value.FieldByName("ClientSecret").SetString("my-secret")
		value.FieldByName("Secret").SetString("0123456789abcdef0123456789abcdef")
	})

	backend := 0
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		backend++
		rw.WriteHeader(http.StatusOK)
	})

	var handler reflect.Value

	func() {
		defer func() {
			if r := recover(); r != nil {
				fail("New panicked: %v", r)
			}
		}()

		handler = callNew(newFn, cfg, next, "yaegicheck")
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("Accept", "text/html")

	func() {
		defer func() {
			if r := recover(); r != nil {
				fail("ServeHTTP panicked: %v", r)
			}
		}()
		handler.MethodByName("ServeHTTP").Call([]reflect.Value{reflect.ValueOf(rec), reflect.ValueOf(req)})
	}()

	if rec.Code != http.StatusInternalServerError {
		fail("expected a 500 when the discovery is unreachable, got %d", rec.Code)
	}
	if backend != 0 {
		fail("the request must not reach the backend, got %d hits", backend)
	}

	fmt.Println("OK: the unreachable provider is reported as a 500, no panic")
}

// checkConfigurationErrors makes sure that an invalid configuration is rejected
// with an error whose message reaches the caller (Traefik reports it in the
// configuration status). Yaegi 0.16.1 can lose the error of a multi-value call
// forwarded from an exported function, so this is checked explicitly.
func checkConfigurationErrors(i *interp.Interpreter, newFn reflect.Value) {
	fmt.Println("=== configuration errors must reach the caller ===")

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })

	cases := []struct {
		name   string
		mutate func(value reflect.Value)
		want   string
	}{
		{
			name:   "missing issuer",
			mutate: func(value reflect.Value) { value.FieldByName("Issuer").SetString("") },
			want:   "issuer",
		},
		{
			name: "Redis Cluster is not supported",
			mutate: func(value reflect.Value) {
				store := reflect.New(value.FieldByName("Store").Type().Elem())
				redisCfg := reflect.New(store.Elem().FieldByName("Redis").Type().Elem())
				redisCfg.Elem().FieldByName("Endpoints").Set(reflect.ValueOf([]string{"redis:6379"}))
				redisCfg.Elem().FieldByName("Cluster").SetString("true")
				store.Elem().FieldByName("Redis").Set(redisCfg)
				value.FieldByName("Store").Set(store)
			},
			want: "Redis Cluster",
		},
	}

	for _, tc := range cases {
		cfg := createConfig(i, func(value reflect.Value) {
			value.FieldByName("Issuer").SetString("https://idp.example.com")
			value.FieldByName("RedirectURL").SetString("/callback")
			value.FieldByName("ClientID").SetString("traefik")
			value.FieldByName("ClientSecret").SetString("my-secret")
			value.FieldByName("Secret").SetString("0123456789abcdef0123456789abcdef")
		})

		tc.mutate(cfg.Elem())

		results := newFn.Call([]reflect.Value{
			reflect.ValueOf(context.Background()),
			reflect.ValueOf(next),
			cfg,
			reflect.ValueOf("yaegicheck-error"),
		})

		if len(results) < 2 || results[1].IsNil() {
			fail("%s: New returned no error (handler nil: %v): Traefik would report a nil handler", tc.name, results[0].IsNil())
		}

		message := fmt.Sprintf("%v", results[1].Interface())
		if !strings.Contains(message, tc.want) {
			fail("%s: error = %q, want it to contain %q", tc.name, message, tc.want)
		}

		fmt.Printf("%-32s -> error surfaced: %s\n", tc.name, message)
	}

	fmt.Println("OK: configuration errors reach the caller with their message")
}

func createConfig(i *interp.Interpreter, configure func(value reflect.Value)) reflect.Value {
	cfg, err := i.Eval("traefik_keycloak_auth.CreateConfig()")
	if err != nil {
		fail("CreateConfig: %v", err)
	}
	configure(cfg.Elem())
	return cfg
}

func callNew(newFn reflect.Value, cfg reflect.Value, next http.Handler, name string) reflect.Value {
	results := newFn.Call([]reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.ValueOf(next),
		cfg,
		reflect.ValueOf(name),
	})
	if len(results) > 1 && !results[1].IsNil() {
		fail("New returned an error: %v", results[1].Interface())
	}
	return results[0]
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, ".traefik.yml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no .traefik.yml found above the working directory")
		}
		dir = parent
	}
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "example", "tools", "docs", ".gocache", ".gotmp", ".gomodcache", ".gopath":
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
}

func fail(format string, args ...interface{}) {
	fmt.Printf("FAILED: "+format+"\n", args...)
	os.Exit(1)
}
