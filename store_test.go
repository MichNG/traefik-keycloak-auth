package traefik_keycloak_auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/oidc"
	"github.com/MichNG/traefik-keycloak-auth/internal/session"
)

// failingStorage always reports an unavailable store.
type failingStorage struct{}

func (failingStorage) StoreSession(*logging.Logger, *config.Config, string, *session.SessionState) (string, error) {
	return "", session.ErrSessionStoreUnavailable
}

func (failingStorage) TryGetSession(*logging.Logger, *config.Config, string) (*session.SessionState, error) {
	return nil, session.ErrSessionStoreUnavailable
}

func testAuthWithStorage(storage session.SessionStorage) *TraefikOidcAuth {
	return &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:            "0123456789abcdef0123456789abcdef",
			SessionCookieName: "toa-session",
			Provider:          &config.ProviderConfig{TokenValidation: "IdToken"},
		},
		SessionStorage: storage,
	}
}

// A store outage must be classified, so ServeHTTP can fail closed with a 503
// instead of forcing every user through a re-login (N2).
func TestGetSessionForRequest_StoreUnavailableIsClassified(t *testing.T) {
	toa := testAuthWithStorage(failingStorage{})

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "toa-session", Value: "ticket"})

	_, _, _, err := toa.getSessionForRequest(req)
	if err == nil {
		t.Fatal("expected an error from the unavailable store")
	}
	if !sessionStoreUnavailable(err) {
		t.Fatalf("error %v is not classified as a store outage", err)
	}
}

// forwardAccessToken is opt-in (N1).
func TestAttachForwardHeaders_ForwardAccessToken(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{ForwardAccessToken: true},
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	toa.attachForwardHeaders(req, &session.SessionState{AccessToken: "the-token", IsAuthorized: true}, nil)

	if got := req.Header.Get("Authorization"); got != "Bearer the-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer the-token")
	}
}

func TestAttachForwardHeaders_ForwardAccessTokenDisabled(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{},
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	toa.attachForwardHeaders(req, &session.SessionState{AccessToken: "the-token", IsAuthorized: true}, nil)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want it unset", got)
	}
}

// The 503 branch must be reachable from the handler: a store outage is not an
// unauthenticated request (N5).
func TestServeHTTP_StoreUnavailableReturns503(t *testing.T) {
	toa := testAuthWithStorage(failingStorage{})

	callback, err := url.Parse("https://app.example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback
	toa.DiscoveryDocument = &oidc.OidcDiscovery{}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "toa-session", Value: "ticket"})

	rw := httptest.NewRecorder()
	toa.ServeHTTP(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rw.Code)
	}
}

// Storing a session must fail closed with the same status as reading one: a
// store outage is retryable, not an internal error (R12 consistency).
func TestStoreSessionAndAttachCookie_StoreUnavailableReturns503(t *testing.T) {
	toa := testAuthWithStorage(failingStorage{})

	rw := httptest.NewRecorder()
	if toa.storeSessionAndAttachCookie(&session.SessionState{Id: "s1"}, rw) {
		t.Fatal("storeSessionAndAttachCookie reported success for an unavailable store")
	}

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rw.Code)
	}
}

// A session that reads fine but cannot be renewed (e.g. the sliding renewal
// hits a read-only node during a failover) must not fail the request: the
// session is valid, so the request is served (N10'/failover availability).
type readOnlyStorage struct {
	session *session.SessionState
}

func (readOnlyStorage) StoreSession(*logging.Logger, *config.Config, string, *session.SessionState) (string, error) {
	return "", session.ErrSessionStoreUnavailable
}

func (s readOnlyStorage) TryGetSession(*logging.Logger, *config.Config, string) (*session.SessionState, error) {
	return s.session, nil
}

func TestServeHTTP_SlidingRenewalFailureIsTolerated(t *testing.T) {
	introspection := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"sub":"testuser"}`))
	}))
	defer introspection.Close()

	forwarded := false
	var next http.HandlerFunc = func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}

	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:            "0123456789abcdef0123456789abcdef",
			SessionCookieName: "toa-session",
			SessionSliding:    true,
			Authorization:     &config.AuthorizationConfig{},
			Provider: &config.ProviderConfig{
				TokenValidation: "Introspection",
			},
		},
		SessionStorage: readOnlyStorage{session: &session.SessionState{
			Id:           "s1",
			AccessToken:  "opaque-token",
			IsAuthorized: true,
			RefreshedAt:  time.Now(),
		}},
		DiscoveryDocument: &oidc.OidcDiscovery{IntrospectionEndpoint: introspection.URL},
		httpClient:        introspection.Client(),
		next:              next,
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "toa-session", Value: "ticket"})

	callback, err := url.Parse("https://app.example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	rw := httptest.NewRecorder()
	toa.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the renewal failure must not fail the request)", rw.Code)
	}
	if !forwarded {
		t.Fatal("the request was not forwarded upstream although the session was valid")
	}
}

// The callback path must fail closed when the session cannot be persisted: a
// session cookie whose ticket points at nothing would send the browser into a
// login loop, so the callback must answer 503 and not redirect (N17').
func TestHandleCallback_StoreFailureReturns503WithoutRedirect(t *testing.T) {
	server := newTokenTestServer(t)
	toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
	toa.SessionStorage = readOnlyStorage{}

	state := &oidc.OidcState{Action: "Login", RedirectUrl: "/"}
	rw := callbackWithState(t, toa, state, "code=abc", "")

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 (body=%s)", rw.Code, rw.Body.String())
	}
	if location := rw.Header().Get("Location"); location != "" {
		t.Fatalf("Location=%q, want no redirect after a failed session store", location)
	}
}

// The configured login/logout path must match exactly or as a parent of the
// request path, not as a bare string prefix (N7': `/login` must not match
// `/login-x`).
func TestMatchesConfiguredURL_PathIsExactOrSubPath(t *testing.T) {
	tests := []struct {
		configured string
		path       string
		want       bool
	}{
		{configured: "/login", path: "/login", want: true},
		{configured: "/login", path: "/login/callback", want: true},
		{configured: "/login", path: "/login-x", want: false},
		{configured: "/login", path: "/login-evil", want: false},
		{configured: "/login/", path: "/login/foo", want: true},
		{configured: "/", path: "/anything", want: true},
		{configured: "https://app.example.com/login", path: "/login", want: true},
		{configured: "https://other.example.com/login", path: "/login", want: false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com"+tc.path, nil)
		if got := matchesConfiguredURL(req, tc.configured); got != tc.want {
			t.Fatalf("matchesConfiguredURL(%q, %q) = %v, want %v", tc.configured, tc.path, got, tc.want)
		}
	}
}

// The bearer token must not be handed to the upstream for a session that
// failed the authorization check (N1').
func TestAttachForwardHeaders_BearerRequiresAuthorized(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{ForwardAccessToken: true},
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	toa.attachForwardHeaders(req, &session.SessionState{AccessToken: "the-token", IsAuthorized: false}, nil)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want it unset for an unauthorized session", got)
	}
}
