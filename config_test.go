package traefik_keycloak_auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichNG/traefik-keycloak-auth/internalconfig"
)

func newTestConfig() *internalconfig.Config {
	cfg := internalconfig.Default()
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Issuer = "https://idp.example.com"
	cfg.ClientID = "my-client"
	cfg.ClientSecret = "my-secret"
	cfg.RedirectURL = "/callback"

	return cfg
}

// The plugin catalog runs the plugin with the `testData` of .traefik.yml as a
// startup validity test, in an environment without Redis and without Keycloak:
// building the middleware must not require any live dependency (both the Redis
// client and the discovery are lazy), and the first request must report the
// unreachable provider as a 500 instead of panicking.
func TestNew_ManifestTestDataWithoutLiveDependencies(t *testing.T) {
	cfg := internalconfig.Default()
	cfg.Issuer = "https://keycloak.example.com/realms/myrealm"
	cfg.RedirectURL = "/callback"
	cfg.ClientID = "traefik"
	cfg.ClientSecret = "my-client-secret"
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Scopes = []string{"openid", "profile", "email"}
	cfg.PKCE = true
	cfg.UsernameClaim = "preferred_username"
	cfg.ForwardHeaders = map[string]string{"X-Auth-User": "preferred_username"}
	cfg.Claims = "OneOf(`access_token.realm_access.roles`, `admin`)"
	cfg.Session = &internalconfig.SessionConfig{
		Expiry:  86400,
		Sliding: true,
		Refresh: true,
		Store: &internalconfig.StoreConfig{Redis: &internalconfig.RedisStoreConfig{
			Endpoints: []string{"redis:6379"},
		}},
	}

	handler, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("the manifest testData must build a middleware without live dependencies: %v", err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("an unreachable issuer must be reported as a 500, got %d", rw.Code)
	}
}

func TestNew_RejectsUnknownTokenValidation(t *testing.T) {
	cfg := newTestConfig()
	cfg.TokenValidation = "Nonsense"

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("expected an unknown TokenValidation to be rejected")
	}
}

func TestNew_AcceptsKnownTokenValidation(t *testing.T) {
	for _, tokenValidation := range []string{"AccessToken", "IdToken", "Introspection"} {
		cfg := newTestConfig()
		cfg.TokenValidation = tokenValidation

		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err != nil {
			t.Errorf("expected TokenValidation %s to be accepted, got %v", tokenValidation, err)
		}
	}
}

func TestNew_RejectsMissingRequiredOptions(t *testing.T) {
	for _, missing := range []string{"issuer", "redirectUrl", "clientID", "clientSecret"} {
		cfg := newTestConfig()
		switch missing {
		case "issuer":
			cfg.Issuer = ""
		case "redirectUrl":
			cfg.RedirectURL = ""
		case "clientID":
			cfg.ClientID = ""
		case "clientSecret":
			cfg.ClientSecret = ""
		}

		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Errorf("expected a missing %s to be rejected", missing)
		}
	}
}

func TestNew_ParsesHeaderTemplatesUpfront(t *testing.T) {
	cfg := newTestConfig()
	cfg.Headers = []internalconfig.HeaderTemplate{
		{Name: "X-Subject", Value: "{{ .claims.sub }}"},
		{Name: "X-Roles", Values: "{{ .claims.roles | mapToJsonArray }}"},
		{Name: "X-Empty"},
	}

	handler, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	internal := handler.(*TraefikOidcAuth).Config
	if internal.Headers[0].Template == nil || internal.Headers[1].Template == nil {
		t.Error("expected the header templates to be parsed while loading the config")
	}

	if internal.Headers[2].Template != nil {
		t.Error("expected no template for a header without a value")
	}
}

func TestNew_RejectsInvalidHeaderTemplate(t *testing.T) {
	cfg := newTestConfig()
	cfg.Headers = []internalconfig.HeaderTemplate{
		{Name: "X-Broken", Value: "{{ .claims.sub "},
	}

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("expected an invalid header template to be rejected")
	}
}

func TestNew_RejectsRedisCluster(t *testing.T) {
	cfg := newTestConfig()
	cfg.Store = &internalconfig.StoreConfig{
		Redis: &internalconfig.RedisStoreConfig{
			Endpoints: []string{"redis:6379"},
			Cluster:   "true",
		},
	}

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("expected session.store.redis.cluster (Enable Redis Cluster) to be rejected")
	}
}

func TestNew_CookieStorageByDefault(t *testing.T) {
	handler, err := New(context.Background(), http.NotFoundHandler(), newTestConfig(), "test")
	if err != nil {
		t.Fatal(err)
	}

	toa := handler.(*TraefikOidcAuth)
	if toa.Config.SessionStorageType != "Cookie" {
		t.Errorf("expected the cookie storage by default, got %q", toa.Config.SessionStorageType)
	}
	if toa.Revoker != nil {
		t.Error("the cookie storage must not expose a Revoker")
	}
}
