package internalconfig

import (
	"strings"
	"testing"
	"time"
)

func valid() *Config {
	cfg := Default()
	cfg.Issuer = "https://keycloak.example.com/realms/myrealm"
	cfg.RedirectURL = "/callback"
	cfg.ClientID = "traefik"
	cfg.ClientSecret = "secret"
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	return cfg
}

func TestAdapt_Defaults(t *testing.T) {
	adapted, err := Adapt(valid())
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}

	cfg := adapted.Config
	if cfg.LogLevel != "WARN" {
		t.Errorf("logLevel = %q, want WARN", cfg.LogLevel)
	}
	if cfg.Provider.TokenValidation != "IdToken" {
		t.Errorf("tokenValidation = %q, want IdToken", cfg.Provider.TokenValidation)
	}
	if cfg.Provider.TokenRenewalThreshold != 0.75 {
		t.Errorf("tokenRenewalThreshold = %v, want 0.75", cfg.Provider.TokenRenewalThreshold)
	}
	if !cfg.Provider.ValidateIssuerBool {
		t.Error("issuer validation must be enabled by default")
	}
	if cfg.Provider.ValidIssuer != "" {
		t.Errorf("validIssuer = %q, want empty (from discovery)", cfg.Provider.ValidIssuer)
	}
	if cfg.SessionExpiry != 86400 {
		t.Errorf("sessionExpiry = %d, want 86400", cfg.SessionExpiry)
	}
	if !cfg.SessionSliding || !cfg.SessionRefresh {
		t.Error("session sliding and refresh must default to true")
	}
	if cfg.StateCookie == nil || cfg.StateCookie.MaxAge != 600 {
		t.Error("stateCookie.maxAge must default to 600")
	}
	if cfg.CSRF != nil {
		t.Error("CSRF must be disabled by default")
	}
	if cfg.SessionStorageType != "Cookie" {
		t.Errorf("session storage = %q, want Cookie", cfg.SessionStorageType)
	}
	if adapted.Redis != nil {
		t.Error("no Redis store must be configured without store.redis")
	}
}

func TestAdapt_MissingRequired(t *testing.T) {
	fields := map[string]func(*Config){
		"issuer":       func(c *Config) { c.Issuer = "" },
		"redirectUrl":  func(c *Config) { c.RedirectURL = "" },
		"clientID":     func(c *Config) { c.ClientID = "" },
		"clientSecret": func(c *Config) { c.ClientSecret = "" },
	}
	for name, mutate := range fields {
		cfg := valid()
		mutate(cfg)
		if _, err := Adapt(cfg); err == nil {
			t.Errorf("missing %s must be rejected", name)
		}
	}
}

func TestAdapt_CSRF_enabledOnlyWhenConfigured(t *testing.T) {
	cfg := valid()
	cfg.CSRF = &CSRFConfig{Secure: true}
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if adapted.Config.CSRF == nil || !adapted.Config.CSRF.Enabled {
		t.Fatal("CSRF must be enabled when csrf is configured")
	}
	if adapted.Config.CSRF.HeaderName != "Hub-Csrf-Token" {
		t.Errorf("csrf header = %q, want the default Hub-Csrf-Token", adapted.Config.CSRF.HeaderName)
	}
}

func TestAdapt_ClaimsExpression(t *testing.T) {
	cfg := valid()
	cfg.Claims = "OneOf(`access_token.realm_access.roles`, `admin`, `media`)"
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if adapted.Claims == nil {
		t.Fatal("the claims expression must be parsed")
	}

	cfg.Claims = "Bogus(`x`, `y`)"
	if _, err := Adapt(cfg); err == nil {
		t.Fatal("an invalid claims expression must be rejected")
	}
}

func TestAdapt_ForwardHeadersAndTokenHeader(t *testing.T) {
	cfg := valid()
	cfg.ForwardHeaders = map[string]string{"X-Auth-User": "preferred_username", "X-Roles": "realm_access.roles"}
	cfg.ForwardIDTokenHeader = "X-Id-Token"
	cfg.UsernameClaim = "preferred_username"

	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if len(adapted.Config.ForwardHeaders) != 2 {
		t.Fatalf("expected 2 forward headers, got %d", len(adapted.Config.ForwardHeaders))
	}
	if adapted.Config.ForwardIDTokenHeader != "X-Id-Token" {
		t.Errorf("forwardIDTokenHeader = %q", adapted.Config.ForwardIDTokenHeader)
	}
	if adapted.Config.UsernameClaim != "preferred_username" {
		t.Errorf("usernameClaim = %q", adapted.Config.UsernameClaim)
	}
}

func TestAdapt_RedisClusterRejected(t *testing.T) {
	cfg := valid()
	cfg.Store = &StoreConfig{Redis: &RedisStoreConfig{Endpoints: []string{"redis:6379"}, Cluster: "true"}}

	if _, err := Adapt(cfg); err == nil {
		t.Fatal("session.store.redis.cluster must be rejected")
	}
}

func TestAdapt_RedisStoreBothSpellings(t *testing.T) {
	// `store.redis.*` — the Distributed RateLimit-like nesting.
	cfg := valid()
	cfg.Store = &StoreConfig{
		KeyPrefix: "toa:",
		Redis:     &RedisStoreConfig{Endpoints: []string{"redis:6379"}, Database: 1},
	}
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt(store.redis): %v", err)
	}
	if adapted.Redis == nil {
		t.Fatal("store.redis must configure the Redis session store")
	}
	if adapted.Redis.KeyPrefix != "toa:" || adapted.Redis.Database != 1 {
		t.Errorf("unexpected Redis options: %+v", adapted.Redis)
	}
	if adapted.Redis.TTL != 86400*time.Second {
		t.Errorf("Redis TTL = %v, want 24h", adapted.Redis.TTL)
	}
	if adapted.Config.SessionStorageType != "Redis" {
		t.Errorf("session storage = %q, want Redis", adapted.Config.SessionStorageType)
	}

	// `session.store.redis.*` — the reference table nesting.
	cfg2 := valid()
	cfg2.Session = &SessionConfig{
		Expiry: 86400,
		Store: &StoreConfig{Redis: &RedisStoreConfig{
			Endpoints: []string{"sentinel-0:26379"},
			Sentinel:  &SentinelConfig{MasterSet: "mymaster"},
		}},
	}
	adapted2, err := Adapt(cfg2)
	if err != nil {
		t.Fatalf("Adapt(session.store.redis): %v", err)
	}
	if adapted2.Redis == nil || adapted2.Redis.Sentinel == nil || adapted2.Redis.Sentinel.MasterSet != "mymaster" {
		t.Fatalf("unexpected Sentinel options: %+v", adapted2.Redis)
	}
}

// `store.redis.tls.*` (and the `session.store.redis.tls.*` synonym) must reach
// the Redis options with the Traefik semantics: a path or inline PEM content,
// `$ENV_VAR` expansion, cert and key together.
func TestAdapt_RedisStoreTLS(t *testing.T) {
	t.Setenv("TRAEFIK_KEYCLOAK_TEST_CA", "/etc/ssl/ca.pem")

	cfg := valid()
	cfg.Store = &StoreConfig{Redis: &RedisStoreConfig{
		Endpoints: []string{"redis:6379"},
		TLS: &RedisTLSConfig{
			CABundle:           "${TRAEFIK_KEYCLOAK_TEST_CA}",
			Cert:               "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
			Key:                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
			InsecureSkipVerify: true,
		},
	}}

	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt(store.redis.tls): %v", err)
	}
	if adapted.Redis == nil || adapted.Redis.TLS == nil {
		t.Fatalf("store.redis.tls must configure the Redis TLS options: %+v", adapted.Redis)
	}
	tls := adapted.Redis.TLS
	if tls.CABundle != "/etc/ssl/ca.pem" {
		t.Errorf("caBundle = %q, want the expanded path", tls.CABundle)
	}
	if !strings.Contains(tls.Cert, "BEGIN CERTIFICATE") || !strings.Contains(tls.Key, "BEGIN PRIVATE KEY") {
		t.Errorf("inline PEM content must be preserved: cert=%q key=%q", tls.Cert, tls.Key)
	}
	if !tls.InsecureSkipVerify {
		t.Error("insecureSkipVerify must be forwarded")
	}

	// The same section nested as in the reference table.
	cfg2 := valid()
	cfg2.Session = &SessionConfig{Expiry: 86400, Store: &StoreConfig{Redis: &RedisStoreConfig{
		Endpoints: []string{"redis:6379"},
		TLS:       &RedisTLSConfig{CABundle: "/etc/ssl/ca.pem"},
	}}}
	adapted2, err := Adapt(cfg2)
	if err != nil {
		t.Fatalf("Adapt(session.store.redis.tls): %v", err)
	}
	if adapted2.Redis == nil || adapted2.Redis.TLS == nil || adapted2.Redis.TLS.CABundle != "/etc/ssl/ca.pem" {
		t.Fatalf("unexpected TLS options: %+v", adapted2.Redis)
	}
}

func TestAdapt_DisableLogin(t *testing.T) {
	cfg := valid()
	cfg.DisableLogin = true
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if adapted.Config.UnauthenticatedBehavior != "Unauthorized" {
		t.Errorf("disableLogin must stop the redirects, got %q", adapted.Config.UnauthenticatedBehavior)
	}
}

func TestAdapt_BackchannelLogout(t *testing.T) {
	cfg := valid()
	cfg.BackchannelLogoutURL = "/backchannel-logout"
	cfg.BackchannelLogoutSessionsRequired = true
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if adapted.Config.BackchannelLogout == nil || !adapted.Config.BackchannelLogout.Enabled {
		t.Fatal("back-channel logout must be enabled")
	}
	if adapted.Config.BackchannelLogout.Path != "/backchannel-logout" {
		t.Errorf("path = %q", adapted.Config.BackchannelLogout.Path)
	}
}

func TestAdapt_SecretLength(t *testing.T) {
	cfg := valid()
	cfg.Secret = "short"
	if _, err := Adapt(cfg); err == nil {
		t.Fatal("a secret that is not 32 characters long must be rejected")
	}
}

func TestAdapt_SessionExpiryZeroRejected(t *testing.T) {
	cfg := valid()
	cfg.Session = &SessionConfig{Expiry: 0}
	if _, err := Adapt(cfg); err == nil {
		t.Fatal("session.expiry: 0 must be rejected")
	}
}

func TestAdapt_StateCookieMaxAgeZeroExpiresImmediately(t *testing.T) {
	cfg := valid()
	cfg.StateCookie = &CookieConfig{MaxAge: 0}
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if adapted.Config.StateCookie.MaxAge != -1 {
		t.Fatalf("stateCookie.maxAge = %d, want -1 (expire immediately)", adapted.Config.StateCookie.MaxAge)
	}
}

func TestAdapt_ForwardAccessTokenAndWildcards(t *testing.T) {
	cfg := valid()
	cfg.ForwardAccessToken = true
	cfg.AllowRedirectUriWildcards = true
	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if !adapted.Config.ForwardAccessToken {
		t.Error("forwardAccessToken must be mapped")
	}
	if !adapted.Config.AllowRedirectUriWildcards {
		t.Error("allowRedirectUriWildcards must be mapped")
	}
}
