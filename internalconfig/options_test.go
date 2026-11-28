package internalconfig

// options_test.go audits every documented option (README "### Options") at the
// adapter level. The audit checks four directions:
//
//   - TestOptions_Defaults             Default() vs the documented default;
//   - TestOptions_Mapping              the option -> internal config mapping;
//   - TestOptions_RedisMapping         the same for store.redis.* (both spellings);
//   - TestOptions_Validation           the invalid values the adapter rejects;
//   - TestOptions_EnvironmentExpansion $ENV_VAR expansion on the secret fields;
//   - TestOptions_DeferredValidation   options the adapter maps but does not
//     validate (the check lives further down the stack).
//
// The per-option file:line references and the "Пробелы" section live in
// docs/21-options-matrix.md; the comments here explain why an option matters.

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// nil-safe navigation helpers: Default() leaves clientConfig.tls, store.redis.*
// and csrf unset, so a leaf under those sections has the Go zero value.
// ---------------------------------------------------------------------------

func optClientTLS(c *Config) ClientTLSConfig {
	if c.ClientConfig == nil || c.ClientConfig.TLS == nil {
		return ClientTLSConfig{}
	}
	return *c.ClientConfig.TLS
}

func optRedis(c *Config) RedisStoreConfig {
	if c.Store == nil || c.Store.Redis == nil {
		return RedisStoreConfig{}
	}
	return *c.Store.Redis
}

func optRedisSentinel(c *Config) SentinelConfig {
	r := optRedis(c)
	if r.Sentinel == nil {
		return SentinelConfig{}
	}
	return *r.Sentinel
}

func optRedisTLS(c *Config) RedisTLSConfig {
	r := optRedis(c)
	if r.TLS == nil {
		return RedisTLSConfig{}
	}
	return *r.TLS
}

func optStateCookie(c *Config) CookieConfig {
	if c.StateCookie == nil {
		return CookieConfig{}
	}
	return *c.StateCookie
}

func optSession(c *Config) SessionConfig {
	if c.Session == nil {
		return SessionConfig{}
	}
	return *c.Session
}

// optEq is a tiny assertion helper: it prints both values on failure.
func optEq(t *testing.T, name string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %#v, want %#v", name, got, want)
	}
}

// ---------------------------------------------------------------------------
// (a) defaults: every leaf, as produced by Default(), next to the README value.
// ---------------------------------------------------------------------------

func TestOptions_Defaults(t *testing.T) {
	cases := []struct {
		name   string // schema path
		readme string // "Default" column of README "### Options"
		get    func(*Config) string
		want   string // what Default() actually produces
	}{
		// --- extensions ---
		{"logLevel", "INFO", func(c *Config) string { return c.LogLevel }, ""},
		{"tokenValidation", "IdToken", func(c *Config) string { return c.TokenValidation }, ""},
		{"tokenRenewalThreshold", "0.75", func(c *Config) string { return fmt.Sprint(c.TokenRenewalThreshold) }, "0"},
		{"useClaimsFromUserInfo", "false", func(c *Config) string { return fmt.Sprint(c.UseClaimsFromUserInfo) }, "false"},
		{"forwardAccessToken", "false", func(c *Config) string { return fmt.Sprint(c.ForwardAccessToken) }, "false"},
		{"allowRedirectUriWildcards", "false", func(c *Config) string { return fmt.Sprint(c.AllowRedirectUriWildcards) }, "false"},
		{"headers.name", "—", func(c *Config) string { return fmt.Sprint(c.Headers) }, "[]"},
		{"headers.value", "—", func(c *Config) string { return fmt.Sprint(c.Headers) }, "[]"},
		{"headers.values", "—", func(c *Config) string { return fmt.Sprint(c.Headers) }, "[]"},
		{"headers.includeWhen", "—", func(c *Config) string { return fmt.Sprint(c.Headers) }, "[]"},

		// --- reference options ---
		{"issuer", "— (required)", func(c *Config) string { return c.Issuer }, ""},
		{"redirectUrl", "— (required)", func(c *Config) string { return c.RedirectURL }, ""},
		{"clientID", "— (required)", func(c *Config) string { return c.ClientID }, ""},
		{"clientSecret", `""`, func(c *Config) string { return c.ClientSecret }, ""},
		{"secret", "— (required)", func(c *Config) string { return c.Secret }, ""},
		{"scopes", `["openid"]`, func(c *Config) string { return fmt.Sprint(c.Scopes) }, "[openid]"},
		{"pkce", "false", func(c *Config) string { return fmt.Sprint(c.PKCE) }, "false"},
		{"loginUrl", "/login", func(c *Config) string { return c.LoginURL }, ""},
		{"logoutUrl", "/logout", func(c *Config) string { return c.LogoutURL }, ""},
		{"postLoginRedirectUrl", `"/"`, func(c *Config) string { return c.PostLoginRedirectURL }, ""},
		{"postLogoutRedirectUrl", `"/"`, func(c *Config) string { return c.PostLogoutRedirectURL }, ""},
		{"disableLogin", "false", func(c *Config) string { return fmt.Sprint(c.DisableLogin) }, "false"},
		{"trustedIssuer", `""`, func(c *Config) string { return c.TrustedIssuer }, ""},
		{"disableIssuerCheck", "false", func(c *Config) string { return fmt.Sprint(c.DisableIssuerCheck) }, "false"},
		{"discoveryParams", "—", func(c *Config) string { return fmt.Sprint(c.DiscoveryParams) }, "map[]"},
		{"authParams", "—", func(c *Config) string { return fmt.Sprint(c.AuthParams) }, "map[]"},
		{"claims", `""`, func(c *Config) string { return c.Claims }, ""},
		{"forwardHeaders", "—", func(c *Config) string { return fmt.Sprint(c.ForwardHeaders) }, "map[]"},
		{"forwardIDTokenHeader", `""`, func(c *Config) string { return c.ForwardIDTokenHeader }, ""},
		{"usernameClaim", "preferred_username", func(c *Config) string { return c.UsernameClaim }, ""},
		{"identity", "sub", func(c *Config) string { return c.Identity }, ""},
		{"backchannelLogoutUrl", `""`, func(c *Config) string { return c.BackchannelLogoutURL }, ""},
		{"backchannelLogoutSessionsRequired", "false", func(c *Config) string { return fmt.Sprint(c.BackchannelLogoutSessionsRequired) }, "false"},

		// --- clientConfig ---
		{"clientConfig.timeoutSeconds", "5", func(c *Config) string { return fmt.Sprint(c.ClientConfig.TimeoutSeconds) }, "5"},
		{"clientConfig.maxRetries", "3", func(c *Config) string { return fmt.Sprint(c.ClientConfig.MaxRetries) }, "3"},
		{"clientConfig.tls.ca", `""`, func(c *Config) string { return optClientTLS(c).CA }, ""},
		{"clientConfig.tls.cert", `""`, func(c *Config) string { return optClientTLS(c).Cert }, ""},
		{"clientConfig.tls.key", `""`, func(c *Config) string { return optClientTLS(c).Key }, ""},
		{"clientConfig.tls.insecureSkipVerify", "false", func(c *Config) string { return fmt.Sprint(optClientTLS(c).InsecureSkipVerify) }, "false"},

		// --- stateCookie ---
		{"stateCookie.name", "toa-state", func(c *Config) string { return optStateCookie(c).Name }, ""},
		{"stateCookie.path", "/", func(c *Config) string { return optStateCookie(c).Path }, "/"},
		{"stateCookie.domain", `""`, func(c *Config) string { return optStateCookie(c).Domain }, ""},
		{"stateCookie.maxAge", "600", func(c *Config) string { return fmt.Sprint(optStateCookie(c).MaxAge) }, "600"},
		{"stateCookie.sameSite", "lax", func(c *Config) string { return optStateCookie(c).SameSite }, "lax"},
		{"stateCookie.httpOnly", "true", func(c *Config) string { return fmt.Sprint(optStateCookie(c).HTTPOnly) }, "true"},
		{"stateCookie.secure", "false", func(c *Config) string { return fmt.Sprint(optStateCookie(c).Secure) }, "false"},

		// --- session ---
		{"session.name", "toa-session", func(c *Config) string { return optSession(c).Name }, ""},
		{"session.path", "/", func(c *Config) string { return optSession(c).Path }, "/"},
		{"session.domain", `""`, func(c *Config) string { return optSession(c).Domain }, ""},
		{"session.expiry", "86400", func(c *Config) string { return fmt.Sprint(optSession(c).Expiry) }, "86400"},
		{"session.sliding", "true", func(c *Config) string { return fmt.Sprint(optSession(c).Sliding) }, "true"},
		{"session.refresh", "true", func(c *Config) string { return fmt.Sprint(optSession(c).Refresh) }, "true"},
		{"session.maxAge", "0", func(c *Config) string { return fmt.Sprint(optSession(c).MaxAge) }, "0"},
		{"session.sameSite", "lax", func(c *Config) string { return optSession(c).SameSite }, "lax"},
		{"session.httpOnly", "true", func(c *Config) string { return fmt.Sprint(optSession(c).HTTPOnly) }, "true"},
		{"session.secure", "false", func(c *Config) string { return fmt.Sprint(optSession(c).Secure) }, "false"},

		// --- session.store.redis / store.redis ---
		{"store.keyPrefix", "traefik-keycloak-auth:", func(*Config) string { var s StoreConfig; return s.GetKeyPrefix() }, "traefik-keycloak-auth:"},
		{"store.redis.endpoints", "—", func(c *Config) string { return fmt.Sprint(optRedis(c).Endpoints) }, "[]"},
		{"store.redis.username", `""`, func(c *Config) string { return optRedis(c).Username }, ""},
		{"store.redis.password", `""`, func(c *Config) string { return optRedis(c).Password }, ""},
		{"store.redis.database", "0", func(c *Config) string { return fmt.Sprint(optRedis(c).Database) }, "0"},
		{"store.redis.cluster", "—", func(c *Config) string { return optRedis(c).Cluster }, ""},
		{"store.redis.sentinel.masterSet", "— (required with Sentinel)", func(c *Config) string { return optRedisSentinel(c).MasterSet }, ""},
		{"store.redis.sentinel.username", `""`, func(c *Config) string { return optRedisSentinel(c).Username }, ""},
		{"store.redis.sentinel.password", `""`, func(c *Config) string { return optRedisSentinel(c).Password }, ""},
		{"store.redis.tls.caBundle", `""`, func(c *Config) string { return optRedisTLS(c).CABundle }, ""},
		{"store.redis.tls.cert", `""`, func(c *Config) string { return optRedisTLS(c).Cert }, ""},
		{"store.redis.tls.key", `""`, func(c *Config) string { return optRedisTLS(c).Key }, ""},
		{"store.redis.tls.insecureSkipVerify", "false", func(c *Config) string { return fmt.Sprint(optRedisTLS(c).InsecureSkipVerify) }, "false"},

		// --- csrf ---
		{"csrf.secure", "false", func(c *Config) string { return fmt.Sprint(c.CSRF != nil && c.CSRF.Secure) }, "false"},
		{"csrf.headerName", "Hub-Csrf-Token", func(c *Config) string {
			if c.CSRF == nil {
				return ""
			}
			return c.CSRF.HeaderName
		}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.get(Default())
			if got != tc.want {
				t.Errorf("Default() leaf %s = %q, want %q", tc.name, got, tc.want)
			}
			if tc.readme != tc.want {
				// The docs and Default() disagree for the options listed here;
				// the effective value comes from the adapter or from New()
				// (see TestOptions_Mapping / docs/21-options-matrix.md).
				t.Logf("%s: README documents %q, Default() yields %q", tc.name, tc.readme, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// (b) mapping: the option reaches the adapted internal configuration.
// ---------------------------------------------------------------------------

func TestOptions_Mapping(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		check  func(*testing.T, *Adapted)
	}{
		// extensions
		{"logLevel", func(c *Config) { c.LogLevel = "DEBUG" }, func(t *testing.T, a *Adapted) {
			optEq(t, "logLevel", a.Config.LogLevel, "DEBUG")
		}},
		{"secret", func(c *Config) { c.Secret = "abcdefghijklmnopqrstuvwxyz012345" }, func(t *testing.T, a *Adapted) {
			optEq(t, "secret", a.Config.Secret, "abcdefghijklmnopqrstuvwxyz012345")
		}},
		{"tokenValidation", func(c *Config) { c.TokenValidation = "Introspection" }, func(t *testing.T, a *Adapted) {
			optEq(t, "tokenValidation", a.Config.Provider.TokenValidation, "Introspection")
		}},
		{"tokenRenewalThreshold", func(c *Config) { c.TokenRenewalThreshold = 0.5 }, func(t *testing.T, a *Adapted) {
			optEq(t, "tokenRenewalThreshold", a.Config.Provider.TokenRenewalThreshold, 0.5)
		}},
		{"useClaimsFromUserInfo", func(c *Config) { c.UseClaimsFromUserInfo = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "useClaimsFromUserInfo", a.Config.Provider.UseClaimsFromUserInfoBool, true)
		}},
		{"headers.name", func(c *Config) {
			c.Headers = []HeaderTemplate{{Name: "X-A", Value: "v", Values: "vs", IncludeWhen: "true"}}
		}, func(t *testing.T, a *Adapted) { optEq(t, "headers.name", a.Config.Headers[0].Name, "X-A") }},
		{"headers.value", func(c *Config) {
			c.Headers = []HeaderTemplate{{Name: "X-A", Value: "v", Values: "vs", IncludeWhen: "true"}}
		}, func(t *testing.T, a *Adapted) { optEq(t, "headers.value", a.Config.Headers[0].Value, "v") }},
		{"headers.values", func(c *Config) {
			c.Headers = []HeaderTemplate{{Name: "X-A", Value: "v", Values: "vs", IncludeWhen: "true"}}
		}, func(t *testing.T, a *Adapted) { optEq(t, "headers.values", a.Config.Headers[0].Values, "vs") }},
		{"headers.includeWhen", func(c *Config) {
			c.Headers = []HeaderTemplate{{Name: "X-A", Value: "v", Values: "vs", IncludeWhen: "true"}}
		}, func(t *testing.T, a *Adapted) {
			optEq(t, "headers.includeWhen", a.Config.Headers[0].IncludeWhen, "true")
		}},
		{"forwardAccessToken", func(c *Config) { c.ForwardAccessToken = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "forwardAccessToken", a.Config.ForwardAccessToken, true)
		}},
		{"allowRedirectUriWildcards", func(c *Config) { c.AllowRedirectUriWildcards = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "allowRedirectUriWildcards", a.Config.AllowRedirectUriWildcards, true)
		}},

		// reference options
		{"issuer", func(c *Config) { c.Issuer = "https://idp.example.com/realms/r" }, func(t *testing.T, a *Adapted) {
			optEq(t, "issuer", a.Config.Provider.Url, "https://idp.example.com/realms/r")
		}},
		{"redirectUrl", func(c *Config) { c.RedirectURL = "/callback" }, func(t *testing.T, a *Adapted) {
			optEq(t, "redirectUrl", a.Config.CallbackUri, "/callback")
		}},
		{"clientID", func(c *Config) { c.ClientID = "client-id" }, func(t *testing.T, a *Adapted) {
			optEq(t, "clientID", a.Config.Provider.ClientId, "client-id")
		}},
		{"clientSecret", func(c *Config) { c.ClientSecret = "client-secret" }, func(t *testing.T, a *Adapted) {
			optEq(t, "clientSecret", a.Config.Provider.ClientSecret, "client-secret")
		}},
		{"scopes", func(c *Config) { c.Scopes = []string{"openid", "profile"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "scopes", a.Config.Scopes, []string{"openid", "profile"})
		}},
		{"pkce", func(c *Config) { c.PKCE = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "pkce", a.Config.Provider.UsePkceBool, true)
		}},
		{"loginUrl", func(c *Config) { c.LoginURL = "/signin" }, func(t *testing.T, a *Adapted) {
			optEq(t, "loginUrl", a.Config.LoginUri, "/signin")
		}},
		{"logoutUrl", func(c *Config) { c.LogoutURL = "/signout" }, func(t *testing.T, a *Adapted) {
			optEq(t, "logoutUrl", a.Config.LogoutUri, "/signout")
		}},
		{"postLoginRedirectUrl", func(c *Config) { c.PostLoginRedirectURL = "/after" }, func(t *testing.T, a *Adapted) {
			optEq(t, "postLoginRedirectUrl", a.Config.PostLoginRedirectUri, "/after")
		}},
		{"postLogoutRedirectUrl", func(c *Config) { c.PostLogoutRedirectURL = "/bye" }, func(t *testing.T, a *Adapted) {
			optEq(t, "postLogoutRedirectUrl", a.Config.PostLogoutRedirectUri, "/bye")
		}},
		{"disableLogin", func(c *Config) { c.DisableLogin = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "disableLogin", a.Config.UnauthenticatedBehavior, "Unauthorized")
		}},
		{"trustedIssuer", func(c *Config) { c.TrustedIssuer = "https://trusted.example.com" }, func(t *testing.T, a *Adapted) {
			optEq(t, "trustedIssuer.validIssuer", a.Config.Provider.ValidIssuer, "https://trusted.example.com")
			optEq(t, "trustedIssuer.trustedIssuer", a.Config.Provider.TrustedIssuer, "https://trusted.example.com")
		}},
		{"disableIssuerCheck", func(c *Config) { c.DisableIssuerCheck = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "disableIssuerCheck", a.Config.Provider.ValidateIssuerBool, false)
		}},
		{"discoveryParams", func(c *Config) { c.DiscoveryParams = map[string]string{"audience": "x"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "discoveryParams", a.Config.Provider.DiscoveryParams, map[string]string{"audience": "x"})
		}},
		{"authParams", func(c *Config) { c.AuthParams = map[string]string{"prompt": "login"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "authParams", a.Config.AuthorizationParams, map[string]string{"prompt": "login"})
		}},
		{"claims", func(c *Config) { c.Claims = "Equals(`a`, `b`)" }, func(t *testing.T, a *Adapted) {
			if a.Claims == nil || a.Config.Authorization.Expr == nil {
				t.Fatal("claims must be parsed into the authorization expression")
			}
		}},
		{"forwardHeaders", func(c *Config) { c.ForwardHeaders = map[string]string{"X-Role": "realm_access.roles"} }, func(t *testing.T, a *Adapted) {
			if len(a.Config.ForwardHeaders) != 1 {
				t.Fatalf("forwardHeaders: got %d entries, want 1", len(a.Config.ForwardHeaders))
			}
			optEq(t, "forwardHeaders.name", a.Config.ForwardHeaders[0].Name, "X-Role")
			optEq(t, "forwardHeaders.claim", a.Config.ForwardHeaders[0].Claim, "realm_access.roles")
		}},
		{"forwardIDTokenHeader", func(c *Config) { c.ForwardIDTokenHeader = "X-ID-Token" }, func(t *testing.T, a *Adapted) {
			optEq(t, "forwardIDTokenHeader", a.Config.ForwardIDTokenHeader, "X-ID-Token")
		}},
		{"usernameClaim", func(c *Config) { c.UsernameClaim = "email" }, func(t *testing.T, a *Adapted) {
			optEq(t, "usernameClaim", a.Config.UsernameClaim, "email")
		}},
		{"identity", func(c *Config) { c.Identity = "email" }, func(t *testing.T, a *Adapted) {
			optEq(t, "identity", a.Config.IdentityClaim, "email")
		}},
		{"backchannelLogoutUrl", func(c *Config) { c.BackchannelLogoutURL = "/backchannel-logout" }, func(t *testing.T, a *Adapted) {
			if a.Config.BackchannelLogout == nil || !a.Config.BackchannelLogout.Enabled {
				t.Fatal("backchannelLogoutUrl must enable the endpoint")
			}
			optEq(t, "backchannelLogoutUrl.path", a.Config.BackchannelLogout.Path, "/backchannel-logout")
		}},
		{"backchannelLogoutSessionsRequired", func(c *Config) {
			c.BackchannelLogoutURL = "/backchannel-logout"
			c.BackchannelLogoutSessionsRequired = true
		}, func(t *testing.T, a *Adapted) {
			optEq(t, "backchannelLogoutSessionsRequired", a.Config.BackchannelLogout.SessionsRequired, true)
		}},

		// clientConfig
		{"clientConfig.timeoutSeconds", func(c *Config) { c.ClientConfig.TimeoutSeconds = 11 }, func(t *testing.T, a *Adapted) {
			optEq(t, "clientConfig.timeoutSeconds", a.Config.Provider.TimeoutSeconds, 11)
		}},
		{"clientConfig.maxRetries", func(c *Config) { c.ClientConfig.MaxRetries = 7 }, func(t *testing.T, a *Adapted) {
			optEq(t, "clientConfig.maxRetries", a.Config.Provider.MaxRetries, 7)
		}},
		{"clientConfig.tls.ca", func(c *Config) { c.ClientConfig.TLS = &ClientTLSConfig{CA: "/etc/ssl/ca.pem"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "clientConfig.tls.ca", a.Config.Provider.CABundle, "/etc/ssl/ca.pem")
		}},
		{"clientConfig.tls.cert", func(c *Config) {
			c.ClientConfig.TLS = &ClientTLSConfig{Cert: "cert.pem", Key: "key.pem"}
		}, func(t *testing.T, a *Adapted) {
			optEq(t, "clientConfig.tls.cert", a.Config.Provider.ClientCert, "cert.pem")
		}},
		{"clientConfig.tls.key", func(c *Config) {
			c.ClientConfig.TLS = &ClientTLSConfig{Cert: "cert.pem", Key: "key.pem"}
		}, func(t *testing.T, a *Adapted) {
			optEq(t, "clientConfig.tls.key", a.Config.Provider.ClientKey, "key.pem")
		}},
		{"clientConfig.tls.insecureSkipVerify", func(c *Config) { c.ClientConfig.TLS = &ClientTLSConfig{InsecureSkipVerify: true} }, func(t *testing.T, a *Adapted) {
			optEq(t, "clientConfig.tls.insecureSkipVerify", a.Config.Provider.InsecureSkipVerifyBool, true)
		}},

		// stateCookie
		{"stateCookie.name", func(c *Config) { c.StateCookie.Name = "my-state" }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.name", a.Config.StateCookieName, "my-state")
		}},
		{"stateCookie.path", func(c *Config) { c.StateCookie.Path = "/app" }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.path", a.Config.StateCookie.Path, "/app")
		}},
		{"stateCookie.domain", func(c *Config) { c.StateCookie.Domain = "example.com" }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.domain", a.Config.StateCookie.Domain, "example.com")
		}},
		{"stateCookie.maxAge", func(c *Config) { c.StateCookie.MaxAge = 120 }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.maxAge", a.Config.StateCookie.MaxAge, 120)
		}},
		{"stateCookie.sameSite", func(c *Config) { c.StateCookie.SameSite = "strict" }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.sameSite", a.Config.StateCookie.SameSite, "strict")
		}},
		{"stateCookie.httpOnly", func(c *Config) { c.StateCookie.HTTPOnly = false }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.httpOnly", a.Config.StateCookie.HttpOnly, false)
		}},
		{"stateCookie.secure", func(c *Config) { c.StateCookie.Secure = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "stateCookie.secure", a.Config.StateCookie.Secure, true)
		}},

		// session
		{"session.name", func(c *Config) { c.Session.Name = "my-session" }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.name", a.Config.SessionCookieName, "my-session")
		}},
		{"session.path", func(c *Config) { c.Session.Path = "/sess" }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.path", a.Config.SessionCookie.Path, "/sess")
		}},
		{"session.domain", func(c *Config) { c.Session.Domain = "example.com" }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.domain", a.Config.SessionCookie.Domain, "example.com")
		}},
		{"session.expiry", func(c *Config) { c.Session.Expiry = 3600 }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.expiry.sessionExpiry", a.Config.SessionExpiry, 3600)
			optEq(t, "session.expiry.cookieMaxAge", a.Config.SessionCookie.MaxAge, 3600)
		}},
		{"session.sliding", func(c *Config) { c.Session.Sliding = false }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.sliding", a.Config.SessionSliding, false)
		}},
		{"session.refresh", func(c *Config) { c.Session.Refresh = false }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.refresh", a.Config.SessionRefresh, false)
		}},
		{"session.maxAge", func(c *Config) { c.Session.MaxAge = 7200 }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.maxAge", a.Config.SessionMaxAge, 7200)
		}},
		{"session.sameSite", func(c *Config) { c.Session.SameSite = "none" }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.sameSite", a.Config.SessionCookie.SameSite, "none")
		}},
		{"session.httpOnly", func(c *Config) { c.Session.HTTPOnly = false }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.httpOnly", a.Config.SessionCookie.HttpOnly, false)
		}},
		{"session.secure", func(c *Config) { c.Session.Secure = true }, func(t *testing.T, a *Adapted) {
			optEq(t, "session.secure", a.Config.SessionCookie.Secure, true)
		}},

		// store.keyPrefix (the value is passed through; New() applies the default)
		{"store.keyPrefix", func(c *Config) {
			c.Store = &StoreConfig{KeyPrefix: "toa:", Redis: &RedisStoreConfig{Endpoints: []string{"redis:6379"}}}
		}, func(t *testing.T, a *Adapted) { optEq(t, "store.keyPrefix", a.Redis.KeyPrefix, "toa:") }},

		// csrf
		{"csrf.secure", func(c *Config) { c.CSRF = &CSRFConfig{Secure: true} }, func(t *testing.T, a *Adapted) {
			optEq(t, "csrf.secure", a.Config.CSRF.Secure, true)
		}},
		{"csrf.headerName", func(c *Config) { c.CSRF = &CSRFConfig{HeaderName: "X-Csrf"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "csrf.headerName", a.Config.CSRF.HeaderName, "X-Csrf")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			adapted, err := Adapt(cfg)
			if err != nil {
				t.Fatalf("Adapt(%s): %v", tc.name, err)
			}
			tc.check(t, adapted)
		})
	}
}

// TestOptions_RedisMapping repeats every `store.redis.*` leaf through both
// documented spellings: `store.redis.*` (the flat synonym) and
// `session.store.redis.*` (the reference nesting).
func TestOptions_RedisMapping(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RedisStoreConfig)
		check  func(*testing.T, *Adapted)
	}{
		{"endpoints", func(r *RedisStoreConfig) { r.Endpoints = []string{"redis:6379"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "endpoints", a.Redis.Endpoints, []string{"redis:6379"})
		}},
		{"username", func(r *RedisStoreConfig) { r.Username = "user" }, func(t *testing.T, a *Adapted) {
			optEq(t, "username", a.Redis.Username, "user")
		}},
		{"password", func(r *RedisStoreConfig) { r.Password = "pass" }, func(t *testing.T, a *Adapted) {
			optEq(t, "password", a.Redis.Password, "pass")
		}},
		{"database", func(r *RedisStoreConfig) { r.Database = 3 }, func(t *testing.T, a *Adapted) {
			optEq(t, "database", a.Redis.Database, 3)
		}},
		{"sentinel.masterSet", func(r *RedisStoreConfig) { r.Sentinel = &SentinelConfig{MasterSet: "mymaster"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "sentinel.masterSet", a.Redis.Sentinel.MasterSet, "mymaster")
		}},
		{"sentinel.username", func(r *RedisStoreConfig) {
			r.Sentinel = &SentinelConfig{MasterSet: "mymaster", Username: "sentinel-user"}
		}, func(t *testing.T, a *Adapted) {
			optEq(t, "sentinel.username", a.Redis.Sentinel.Username, "sentinel-user")
		}},
		{"sentinel.password", func(r *RedisStoreConfig) {
			r.Sentinel = &SentinelConfig{MasterSet: "mymaster", Password: "sentinel-pass"}
		}, func(t *testing.T, a *Adapted) {
			optEq(t, "sentinel.password", a.Redis.Sentinel.Password, "sentinel-pass")
		}},
		{"tls.caBundle", func(r *RedisStoreConfig) { r.TLS = &RedisTLSConfig{CABundle: "/etc/ssl/ca.pem"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "tls.caBundle", a.Redis.TLS.CABundle, "/etc/ssl/ca.pem")
		}},
		{"tls.cert", func(r *RedisStoreConfig) { r.TLS = &RedisTLSConfig{Cert: "cert.pem", Key: "key.pem"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "tls.cert", a.Redis.TLS.Cert, "cert.pem")
		}},
		{"tls.key", func(r *RedisStoreConfig) { r.TLS = &RedisTLSConfig{Cert: "cert.pem", Key: "key.pem"} }, func(t *testing.T, a *Adapted) {
			optEq(t, "tls.key", a.Redis.TLS.Key, "key.pem")
		}},
		{"tls.insecureSkipVerify", func(r *RedisStoreConfig) { r.TLS = &RedisTLSConfig{InsecureSkipVerify: true} }, func(t *testing.T, a *Adapted) {
			optEq(t, "tls.insecureSkipVerify", a.Redis.TLS.InsecureSkipVerify, true)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/store.redis", func(t *testing.T) {
			cfg := valid()
			redis := &RedisStoreConfig{}
			tc.mutate(redis)
			cfg.Store = &StoreConfig{Redis: redis}
			adapted, err := Adapt(cfg)
			if err != nil {
				t.Fatalf("Adapt(store.redis): %v", err)
			}
			if adapted.Redis == nil {
				t.Fatal("store.redis must configure the Redis session store")
			}
			tc.check(t, adapted)
		})

		t.Run(tc.name+"/session.store.redis", func(t *testing.T) {
			cfg := valid()
			redis := &RedisStoreConfig{}
			tc.mutate(redis)
			cfg.Session.Store = &StoreConfig{Redis: redis}
			adapted, err := Adapt(cfg)
			if err != nil {
				t.Fatalf("Adapt(session.store.redis): %v", err)
			}
			if adapted.Redis == nil {
				t.Fatal("session.store.redis must configure the Redis session store")
			}
			tc.check(t, adapted)
		})
	}
}

// TestOptions_StoreSynonymPrecedence pins resolveStore: the nested
// `session.store.*` spelling wins over the flat `store.redis.*` one, and the
// key prefix is taken from the first spelling that sets it.
func TestOptions_StoreSynonymPrecedence(t *testing.T) {
	cfg := valid()
	cfg.Store = &StoreConfig{
		KeyPrefix: "flat:",
		Redis:     &RedisStoreConfig{Endpoints: []string{"flat:6379"}, Database: 1},
	}
	cfg.Session.Store = &StoreConfig{
		Redis: &RedisStoreConfig{Endpoints: []string{"nested:6379"}, Database: 2},
	}

	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	optEq(t, "session.store wins for the endpoints", adapted.Redis.Endpoints, []string{"nested:6379"})
	optEq(t, "session.store wins for the database", adapted.Redis.Database, 2)
	optEq(t, "the first keyPrefix that is set is kept", adapted.Redis.KeyPrefix, "flat:")
}

// ---------------------------------------------------------------------------
// (c) validation: the adapter rejects the value and names the option.
// ---------------------------------------------------------------------------

func TestOptions_Validation(t *testing.T) {
	const clusterMsg = "session.store.redis.cluster"

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantMsg string // the option the error must mention
	}{
		{"issuer required", func(c *Config) { c.Issuer = "" }, "issuer"},
		{"redirectUrl required", func(c *Config) { c.RedirectURL = "" }, "redirectUrl"},
		{"clientID required", func(c *Config) { c.ClientID = "" }, "clientID"},
		{"clientSecret required", func(c *Config) { c.ClientSecret = "" }, "clientSecret"},
		{"secret must be 32 chars", func(c *Config) { c.Secret = "short" }, "secret"},
		{"redirectUrl must parse", func(c *Config) { c.RedirectURL = "http://[::1" }, "redirectUrl"},
		{"store.redis.cluster rejected", func(c *Config) {
			c.Store = &StoreConfig{Redis: &RedisStoreConfig{Endpoints: []string{"redis:6379"}, Cluster: "true"}}
		}, clusterMsg},
		{"session.store.redis.cluster rejected", func(c *Config) {
			c.Session.Store = &StoreConfig{Redis: &RedisStoreConfig{Endpoints: []string{"redis:6379"}, Cluster: "true"}}
		}, clusterMsg},
		{"session.expiry must be > 0", func(c *Config) { c.Session.Expiry = 0 }, "session.expiry"},
		{"session.maxAge must not be negative", func(c *Config) { c.Session.MaxAge = -1 }, "session.maxAge"},
		{"headers entry needs a name", func(c *Config) { c.Headers = []HeaderTemplate{{Value: "v"}} }, "headers"},
		{"forwardHeaders needs both sides", func(c *Config) { c.ForwardHeaders = map[string]string{"": "claim"} }, "forwardHeaders"},
		{"backchannelLogoutUrl must parse", func(c *Config) { c.BackchannelLogoutURL = "://bad" }, "backchannelLogoutUrl"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			_, err := Adapt(cfg)
			if err == nil {
				t.Fatalf("Adapt must reject %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// $ENV_VAR expansion on the secret-carrying fields.
// ---------------------------------------------------------------------------

func TestOptions_EnvironmentExpansion(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" // 32 chars

	t.Setenv("OPT_TEST_SECRET", secret)
	t.Setenv("OPT_TEST_CLIENT_SECRET", "client-secret-from-env")
	t.Setenv("OPT_TEST_REDIS_USER", "redis-user")
	t.Setenv("OPT_TEST_REDIS_PASS", "redis-pass")
	t.Setenv("OPT_TEST_CA", "/etc/ssl/redis-ca.pem")

	cfg := valid()
	cfg.Secret = "${OPT_TEST_SECRET}"
	cfg.ClientSecret = "${OPT_TEST_CLIENT_SECRET}"
	cfg.Store = &StoreConfig{Redis: &RedisStoreConfig{
		Endpoints: []string{"redis:6379"},
		Username:  "${OPT_TEST_REDIS_USER}",
		Password:  "${OPT_TEST_REDIS_PASS}",
		TLS:       &RedisTLSConfig{CABundle: "${OPT_TEST_CA}"},
	}}

	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}

	optEq(t, "secret", adapted.Config.Secret, secret)
	optEq(t, "clientSecret", adapted.Config.Provider.ClientSecret, "client-secret-from-env")
	optEq(t, "redis username", adapted.Redis.Username, "redis-user")
	optEq(t, "redis password", adapted.Redis.Password, "redis-pass")
	optEq(t, "redis tls caBundle", adapted.Redis.TLS.CABundle, "/etc/ssl/redis-ca.pem")
}

// TestOptions_SecretFallsBackToTheDeprecatedDefault pins the historical
// behaviour: an empty `secret` is not rejected, it falls back to DefaultSecret
// (config.go). The README calls `secret` required; the adapter does not.
func TestOptions_SecretFallsBackToTheDeprecatedDefault(t *testing.T) {
	cfg := valid()
	cfg.Secret = ""

	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	optEq(t, "secret", adapted.Config.Secret, DefaultSecret)
}

// ---------------------------------------------------------------------------
// Options the adapter maps but does not validate.
//
// The validation requirement listed for these options is enforced further down
// the stack, not by Adapt: the test pins the adapter behaviour and names the
// real enforcement site, which is what the matrix records as a gap.
// ---------------------------------------------------------------------------

func TestOptions_DeferredValidation(t *testing.T) {
	t.Run("tokenValidation is rejected by New, not by Adapt", func(t *testing.T) {
		cfg := valid()
		cfg.TokenValidation = "Nonsense"
		adapted, err := Adapt(cfg)
		if err != nil {
			t.Fatalf("Adapt must map tokenValidation as-is: %v", err)
		}
		// config.go:150-155 (New) rejects an unknown tokenValidation.
		optEq(t, "tokenValidation", adapted.Config.Provider.TokenValidation, "Nonsense")
	})

	t.Run("tokenRenewalThreshold range is checked by New, not by Adapt", func(t *testing.T) {
		for _, threshold := range []float64{0.2, 1.5} {
			cfg := valid()
			cfg.TokenRenewalThreshold = threshold
			adapted, err := Adapt(cfg)
			if err != nil {
				t.Fatalf("Adapt must map tokenRenewalThreshold as-is: %v", err)
			}
			// config.go:157-160 (New) rejects < 0.5 or > 1.0.
			optEq(t, "tokenRenewalThreshold", adapted.Config.Provider.TokenRenewalThreshold, threshold)
		}
	})

	t.Run("clientConfig.tls cert/key pairing is checked by buildClientTLS, not by Adapt", func(t *testing.T) {
		cfg := valid()
		cfg.ClientConfig.TLS = &ClientTLSConfig{Cert: "cert.pem"}
		adapted, err := Adapt(cfg)
		if err != nil {
			t.Fatalf("Adapt must map clientConfig.tls as-is: %v", err)
		}
		// httpclient.go:163-166 (buildClientTLS) requires cert and key together.
		optEq(t, "clientConfig.tls.cert", adapted.Config.Provider.ClientCert, "cert.pem")
		optEq(t, "clientConfig.tls.key", adapted.Config.Provider.ClientKey, "")
	})

	t.Run("redis tls cert/key pairing is checked by the data plane, not by Adapt", func(t *testing.T) {
		cfg := valid()
		cfg.Store = &StoreConfig{Redis: &RedisStoreConfig{
			Endpoints: []string{"redis:6379"},
			TLS:       &RedisTLSConfig{Cert: "cert.pem"},
		}}
		adapted, err := Adapt(cfg)
		if err != nil {
			t.Fatalf("Adapt must map store.redis.tls as-is: %v", err)
		}
		// internal/redis/tlsconfig.go:70-72 (CreateTLSConfig) requires both.
		optEq(t, "tls.cert", adapted.Redis.TLS.Cert, "cert.pem")
		optEq(t, "tls.key", adapted.Redis.TLS.Key, "")
	})

	t.Run("sentinel.masterSet is required by the session store, not by Adapt", func(t *testing.T) {
		cfg := valid()
		cfg.Session.Store = &StoreConfig{Redis: &RedisStoreConfig{
			Endpoints: []string{"sentinel-0:26379"},
			Sentinel:  &SentinelConfig{},
		}}
		adapted, err := Adapt(cfg)
		if err != nil {
			t.Fatalf("Adapt must map the Sentinel section as-is: %v", err)
		}
		// internal/session/redisSessionStorage.go:98-100 requires masterSet.
		optEq(t, "sentinel.masterSet", adapted.Redis.Sentinel.MasterSet, "")
	})
}

// TestOptions_SessionStoreRequiresEndpoints documents the one difference the
// adapter cannot express: an empty `endpoints` list still configures the Redis
// store, and the failure surfaces when the store is created (New).
func TestOptions_SessionStoreRequiresEndpoints(t *testing.T) {
	cfg := valid()
	cfg.Store = &StoreConfig{Redis: &RedisStoreConfig{}}

	adapted, err := Adapt(cfg)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if adapted.Redis == nil {
		t.Fatal("an empty store.redis section must still select the Redis store")
	}
	optEq(t, "storage", adapted.Config.SessionStorageType, "Redis")
	optEq(t, "ttl follows session.expiry", adapted.Redis.TTL, 86400*time.Second)
}
