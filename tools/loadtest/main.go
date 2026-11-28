// Command loadtest is a stdlib-only load generator for the Traefik OIDC plugin
// end-to-end stack (Keycloak + Redis Sentinel backed sessions).
//
// It drives the real browser authorization-code flow once per session (HTTP +
// cookie jar: GET <base><login-path>, parse the Keycloak form "action", POST the
// credentials, follow the callback until a 200 carrying X-Auth-User), then runs
// C concurrent workers for a given duration against a target path, rotating the
// collected session cookies.
//
// Modes:
//
//	unauth  no sessions at all: plain unauthenticated requests, which exercise
//	        the plugin's 401 path.
//	session log in N sessions and load the Redis-session protected router (default
//	        path "/").
//	cookie  log in N sessions against the cookie-session middleware and load the
//	        /cookie router (default login path /cookie/login, default path /cookie).
//
// It has no third-party dependencies.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// actionRe extracts the "action" attribute of the Keycloak login form.
var actionRe = regexp.MustCompile(`action="([^"]*)"`)

// noRedirect stops the client right after the first response so the caller can
// read the Location header (the login redirect and the callback redirect).
func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

type config struct {
	base        string
	mode        string
	sessions    int
	concurrency int
	duration    time.Duration
	path        string
	loginPath   string
	username    string
	password    string
	timeout     time.Duration
	attempts    int
}

func main() {
	var (
		base        = flag.String("base", "http://localhost:9080", "base URL of the Traefik entrypoint")
		mode        = flag.String("mode", "session", "load mode: unauth | session | cookie")
		sessions    = flag.Int("sessions", 20, "number of logged-in sessions for session/cookie modes")
		concurrency = flag.Int("concurrency", 20, "number of concurrent load workers")
		duration    = flag.Duration("duration", 30*time.Second, "load phase duration")
		path        = flag.String("path", "/", "target path for the load requests")
		loginPath   = flag.String("login-path", "", "login path (default /login, or /cookie/login for cookie mode)")
		username    = flag.String("username", "testuser", "realm username reused for all sessions")
		password    = flag.String("password", "testpassword", "realm password reused for all sessions")
		timeout     = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		attempts    = flag.Int("login-attempts", 3, "bounded login attempts per session")
	)
	flag.Parse()

	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfg := config{
		base:        strings.TrimRight(*base, "/"),
		mode:        *mode,
		sessions:    *sessions,
		concurrency: *concurrency,
		duration:    *duration,
		path:        *path,
		username:    *username,
		password:    *password,
		timeout:     *timeout,
		attempts:    *attempts,
	}

	switch cfg.mode {
	case "unauth", "session", "cookie":
	default:
		fatal("invalid -mode %q (want unauth, session or cookie)", cfg.mode)
	}
	if cfg.concurrency < 1 {
		fatal("-concurrency must be >= 1")
	}
	if cfg.duration <= 0 {
		fatal("-duration must be > 0")
	}

	// Per-mode defaults, unless the user explicitly set the flag.
	cfg.loginPath = *loginPath
	if cfg.loginPath == "" {
		if cfg.mode == "cookie" {
			cfg.loginPath = "/cookie/login"
		} else {
			cfg.loginPath = "/login"
		}
	}
	if !set["path"] && cfg.mode == "cookie" {
		cfg.path = "/cookie"
	}
	if !strings.HasPrefix(cfg.path, "/") {
		cfg.path = "/" + cfg.path
	}
	if !strings.HasPrefix(cfg.loginPath, "/") {
		cfg.loginPath = "/" + cfg.loginPath
	}

	transport := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}
	defer transport.CloseIdleConnections()

	targetURL := cfg.base + cfg.path
	// The parsed target doubles as the cookie scope: the cookie-session
	// middleware sets a path-scoped session cookie, so cookies must be collected
	// for the target path, not just the host root.
	scopeURL, err := url.Parse(targetURL)
	if err != nil || scopeURL.Host == "" {
		fatal("invalid base/target URL %q: %v", targetURL, err)
	}

	fmt.Printf("=== loadtest: mode=%s base=%s target=%s ===\n", cfg.mode, cfg.base, targetURL)

	// ---------------------------------------------------------------------
	// Sessions.
	var sessCookies [][]*http.Cookie
	if cfg.mode != "unauth" {
		if cfg.sessions < 1 {
			fatal("mode %s needs -sessions >= 1", cfg.mode)
		}
		sessCookies = loginAll(transport, scopeURL, &cfg)
		if len(sessCookies) == 0 {
			fatal("no session could be established; aborting")
		}
		fmt.Printf("logged in %d/%d sessions\n", len(sessCookies), cfg.sessions)
	} else {
		fmt.Printf("unauth mode: no sessions, plain requests (expect HTTP 401)\n")
	}

	// ---------------------------------------------------------------------
	// Load phase.
	stats := runLoad(transport, targetURL, sessCookies, &cfg)
	report(targetURL, len(sessCookies), &cfg, stats)
}

// ---------------------------------------------------------------------------
// Login

// loginAll logs in cfg.sessions sessions concurrently (bounded to 8 at a time),
// each with its own cookie jar, retrying a bounded number of times.
func loginAll(transport *http.Transport, baseURL *url.URL, cfg *config) [][]*http.Cookie {
	out := make([][]*http.Cookie, cfg.sessions)
	var wg sync.WaitGroup
	sem := make(chan struct{}, min(cfg.sessions, 8))
	var ok int64

	for i := 0; i < cfg.sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var lastErr error
			for attempt := 1; attempt <= cfg.attempts; attempt++ {
				jar, err := cookiejar.New(nil)
				if err != nil {
					lastErr = err
					break
				}
				if err := loginOnce(transport, jar, cfg, baseURL.Host); err != nil {
					lastErr = err
					time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
					continue
				}
				cookies := jar.Cookies(baseURL)
				if len(cookies) == 0 {
					lastErr = errors.New("no cookies captured after login")
					continue
				}
				out[i] = cookies
				atomic.AddInt64(&ok, 1)
				return
			}
			fmt.Fprintf(os.Stderr, "session %d login failed: %v\n", i, lastErr)
		}(i)
	}
	wg.Wait()

	got := make([][]*http.Cookie, 0, cfg.sessions)
	for _, s := range out {
		if len(s) > 0 {
			got = append(got, s)
		}
	}
	return got
}

// loginOnce runs the full browser flow for one session. It succeeds as soon as a
// 200 response served by the plugin host itself carries X-Auth-User, either while
// following the callback or, as a fallback, while probing the protected target
// path (the cookie middleware redirects to "/" after the callback, so the
// fallback matters there).
//
// The cookie middleware of the shipped stack (oidc-cookie) does not configure
// forwardHeaders, so its upstream response has no X-Auth-User; for cookie mode a
// 200 served by the plugin host is the success signal. A 200 that is really
// Keycloak's login page is rejected because it is served by a different host.
func loginOnce(transport *http.Transport, jar http.CookieJar, cfg *config, baseHost string) error {
	noRedir := &http.Client{Jar: jar, Transport: transport, Timeout: cfg.timeout, CheckRedirect: noRedirect}
	follow := &http.Client{Jar: jar, Transport: transport, Timeout: cfg.timeout}

	ok := func(resp *http.Response, body []byte) bool {
		if resp == nil || resp.StatusCode != http.StatusOK {
			return false
		}
		if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Host != baseHost {
			return false
		}
		if cfg.mode == "cookie" {
			return true
		}
		return strings.Contains(string(body), "X-Auth-User")
	}

	loginURL := cfg.base + cfg.loginPath
	req, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		return err
	}
	resp, body, err := do(noRedir, req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", cfg.loginPath, err)
	}
	if ok(resp, body) {
		return nil // already authenticated
	}
	authURL := resp.Header.Get("Location")
	if authURL == "" {
		return fmt.Errorf("GET %s: no redirect (status %d)", cfg.loginPath, resp.StatusCode)
	}
	authURL = resolve(loginURL, authURL)

	req, err = http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		return err
	}
	resp, body, err = do(follow, req)
	if err != nil {
		return fmt.Errorf("GET Keycloak auth page: %w", err)
	}
	action := extractAction(body)
	if action == "" {
		return fmt.Errorf("Keycloak login form not found (status %d)", resp.StatusCode)
	}
	action = resolve(authURL, action)

	form := url.Values{
		"username":     {cfg.username},
		"password":     {cfg.password},
		"credentialId": {""},
	}
	req, err = http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _, err = do(noRedir, req)
	if err != nil {
		return fmt.Errorf("POST credentials: %w", err)
	}

	if cb := resp.Header.Get("Location"); cb != "" {
		cb = resolve(action, cb)
		req, err = http.NewRequest(http.MethodGet, cb, nil)
		if err != nil {
			return err
		}
		if resp, body, err = do(follow, req); err == nil && ok(resp, body) {
			return nil
		}
	}

	// Fallback: probe the protected target with the accumulated cookies.
	req, err = http.NewRequest(http.MethodGet, cfg.base+cfg.path, nil)
	if err != nil {
		return err
	}
	resp, body, err = do(follow, req)
	if err != nil {
		return fmt.Errorf("probe %s: %w", cfg.path, err)
	}
	if ok(resp, body) {
		return nil
	}
	return fmt.Errorf("login did not yield an authenticated session (probe status %d)", resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Load

type stats struct {
	lats     []time.Duration
	statuses map[int]int
	total    int
	timeouts int
	connErr  int
	wall     time.Duration
}

// runLoad starts cfg.concurrency workers that issue GETs to targetURL until the
// deadline, rotating the provided session cookies.
func runLoad(transport *http.Transport, targetURL string, sessions [][]*http.Cookie, cfg *config) *stats {
	client := &http.Client{Transport: transport, Timeout: cfg.timeout}
	deadline := time.Now().Add(cfg.duration)

	var next int64
	perWorker := make([]*stats, cfg.concurrency)
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < cfg.concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			st := &stats{statuses: make(map[int]int)}
			perWorker[w] = st

			for time.Now().Before(deadline) {
				ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
				if err != nil {
					cancel()
					st.connErr++
					continue
				}
				if len(sessions) > 0 {
					idx := int(atomic.AddInt64(&next, 1)-1) % len(sessions)
					for _, c := range sessions[idx] {
						req.AddCookie(c)
					}
				}

				reqStart := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					st.total++
					if isTimeout(err) {
						st.timeouts++
					} else {
						st.connErr++
					}
					cancel()
					continue
				}
				_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				elapsed := time.Since(reqStart)
				cancel()

				st.total++
				st.statuses[resp.StatusCode]++
				if readErr != nil {
					if isTimeout(readErr) {
						st.timeouts++
					} else {
						st.connErr++
					}
					continue
				}
				st.lats = append(st.lats, elapsed)
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	merged := &stats{statuses: make(map[int]int)}
	for _, st := range perWorker {
		if st == nil {
			continue
		}
		merged.total += st.total
		merged.timeouts += st.timeouts
		merged.connErr += st.connErr
		merged.lats = append(merged.lats, st.lats...)
		for code, n := range st.statuses {
			merged.statuses[code] += n
		}
	}
	merged.wall = elapsed
	return merged
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ---------------------------------------------------------------------------
// Reporting

func report(targetURL string, nSessions int, cfg *config, st *stats) {
	sort.Slice(st.lats, func(i, j int) bool { return st.lats[i] < st.lats[j] })

	var sum time.Duration
	for _, d := range st.lats {
		sum += d
	}
	mean := time.Duration(0)
	if len(st.lats) > 0 {
		mean = sum / time.Duration(len(st.lats))
	}

	rps := 0.0
	if st.wall > 0 {
		rps = float64(st.total) / st.wall.Seconds()
	}

	fmt.Printf("\n=== load test report ===\n")
	fmt.Printf("mode          : %s\n", cfg.mode)
	fmt.Printf("target        : %s\n", targetURL)
	if cfg.mode == "unauth" {
		fmt.Printf("sessions      : 0 (unauthenticated)\n")
	} else {
		fmt.Printf("sessions      : %d logged in\n", nSessions)
	}
	fmt.Printf("concurrency   : %d\n", cfg.concurrency)
	fmt.Printf("duration      : %s (wall %s)\n", cfg.duration, st.wall.Round(time.Millisecond))
	fmt.Printf("total requests: %d\n", st.total)
	fmt.Printf("RPS           : %.2f\n", rps)
	fmt.Printf("latency ms    : min=%.2f mean=%.2f p50=%.2f p90=%.2f p95=%.2f p99=%.2f max=%.2f\n",
		ms(percentile(st.lats, 0)), ms(mean), ms(percentile(st.lats, 50)),
		ms(percentile(st.lats, 90)), ms(percentile(st.lats, 95)),
		ms(percentile(st.lats, 99)), ms(percentile(st.lats, 100)))
	fmt.Printf("status codes  :\n")
	codes := make([]int, 0, len(st.statuses))
	for code := range st.statuses {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		n := st.statuses[code]
		pct := 0.0
		if st.total > 0 {
			pct = 100 * float64(n) / float64(st.total)
		}
		fmt.Printf("  %3d: %d (%.1f%%)\n", code, n, pct)
	}
	if len(codes) == 0 {
		fmt.Printf("  (none)\n")
	}
	fmt.Printf("errors        : timeouts=%d connection=%d\n", st.timeouts, st.connErr)
	fmt.Printf("=== end of report ===\n")
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// Helpers

func do(client *http.Client, req *http.Request) (*http.Response, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp, nil, err
	}
	return resp, body, nil
}

func extractAction(body []byte) string {
	m := actionRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return html.UnescapeString(string(m[1]))
}

func resolve(base, ref string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return bu.ResolveReference(ru).String()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "loadtest: "+format+"\n", args...)
	os.Exit(1)
}
