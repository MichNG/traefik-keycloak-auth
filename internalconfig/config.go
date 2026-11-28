// Package internalconfig defines the middleware configuration schema.
//
// The field names deliberately mirror the Traefik Hub "OpenID Connect
// Authentication" middleware reference
// (https://doc.traefik.io/traefik-hub/api-gateway/reference/routing/http/middlewares/ref-oidc),
// so that an existing Hub configuration can be used with this plugin after
// renaming the middleware key. Every option of the reference is represented
// here with the same name, the same semantics and the same default value,
// with a single, deliberate exception: `store.redis.cluster` ("Enable Redis
// Cluster") is not implemented and configuring it fails the middleware
// creation with an explicit message.
//
// Traefik decodes the plugin configuration with mapstructure (field names are
// matched case-insensitively, `WeaklyTypedInput` is enabled), so the explicit
// `mapstructure` tags below are authoritative.
package internalconfig

// DefaultSecret is kept only so that the value historically shipped as an
// example keeps working; it is never a safe production value.
//
// Deprecated: this option does not exist in the Hub schema anymore. It is kept
// for backward compatibility with the community plugin configuration.
const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

// Config is the plugin configuration (Traefik Hub OIDC schema).
type Config struct {
	// ------------------------------------------------------------------
	// Extensions of this plugin. They do not exist in the Hub reference and
	// are only needed because a middleware plugin runs outside the Hub
	// control plane (it has no managed secret) or because they map to a
	// proven behaviour of the community plugin.
	// ------------------------------------------------------------------

	// LogLevel is the log level: TRACE, DEBUG, INFO, WARN or ERROR.
	LogLevel string `json:"logLevel,omitempty" mapstructure:"logLevel"`
	// Secret is the 32 character secret used to encrypt the OIDC state and the
	// stored sessions. It replaces the secret that Hub manages internally.
	Secret string `json:"secret,omitempty" mapstructure:"secret"`
	// TokenValidation selects the token verified on each request: IdToken
	// (default), AccessToken or Introspection.
	TokenValidation string `json:"tokenValidation,omitempty" mapstructure:"tokenValidation"`
	// TokenRenewalThreshold is the fraction of the token lifetime after which a
	// proactive refresh is attempted (0.5 .. 1.0, default 0.75).
	TokenRenewalThreshold float64 `json:"tokenRenewalThreshold,omitempty" mapstructure:"tokenRenewalThreshold"`
	// UseClaimsFromUserInfo merges the UserInfo claims into the token claims.
	UseClaimsFromUserInfo bool `json:"useClaimsFromUserInfo,omitempty" mapstructure:"useClaimsFromUserInfo"`
	// Headers is an extension: additional upstream headers rendered from a Go
	// template over the claims and the tokens. It is the community plugin
	// equivalent of a richer forwardHeaders.
	Headers []HeaderTemplate `json:"headers,omitempty" mapstructure:"headers"`
	// ForwardAccessToken is an extension: set `Authorization: Bearer <access_token>`
	// on the upstream request, like the reference does implicitly.
	ForwardAccessToken bool `json:"forwardAccessToken,omitempty" mapstructure:"forwardAccessToken"`
	// AllowRedirectUriWildcards is an extension: enable the `*` wildcard in the
	// post-login/logout redirect lists for THIS middleware, instead of the
	// process-wide TOA_ENABLE_REDIRECT_URI_WILDCARDS variable.
	AllowRedirectUriWildcards bool `json:"allowRedirectUriWildcards,omitempty" mapstructure:"allowRedirectUriWildcards"`

	// Issuer is the URL of the OpenID Connect provider, the server which
	// provides the discovery document (issuer + "/.well-known/openid-configuration").
	Issuer string `json:"issuer,omitempty" mapstructure:"issuer"`
	// RedirectURL is the URL the provider redirects back to once the
	// authorization is complete. It may be absolute, or relative to the
	// request protocol / domain.
	RedirectURL string `json:"redirectUrl,omitempty" mapstructure:"redirectUrl"`
	// ClientID is the client identifier registered at the provider.
	ClientID string `json:"clientID,omitempty" mapstructure:"clientID"`
	// ClientSecret is the client secret registered at the provider.
	ClientSecret string `json:"clientSecret,omitempty" mapstructure:"clientSecret"`
	// Claims is the authorization expression evaluated against the token
	// claims (see the claims package for the grammar).
	Claims string `json:"claims,omitempty" mapstructure:"claims"`
	// UsernameClaim is the claim evaluated to populate the user name in the
	// access logs.
	UsernameClaim string `json:"usernameClaim,omitempty" mapstructure:"usernameClaim"`
	// Identity is the claim whose value identifies the caller (used by Hub for
	// cache partitioning). It is accepted and resolved by this plugin, but only
	// exposed through headers/logging: a middleware plugin cannot feed the Hub
	// semantic cache.
	Identity string `json:"identity,omitempty" mapstructure:"identity"`
	// ValidPostLoginRedirectUris / ValidPostLogoutRedirectUris are extensions
	// of this plugin. They list the cross-origin redirect targets accepted after
	// a login/logout; a URL on the callback host is always accepted, and the `*`
	// wildcard is accepted when AllowRedirectUriWildcards (or the
	// TOA_ENABLE_REDIRECT_URI_WILDCARDS variable) is set.
	ValidPostLoginRedirectUris  []string `json:"validPostLoginRedirectUris,omitempty" mapstructure:"validPostLoginRedirectUris"`
	ValidPostLogoutRedirectUris []string `json:"validPostLogoutRedirectUris,omitempty" mapstructure:"validPostLogoutRedirectUris"`

	// ForwardHeaders maps an HTTP header name to a claim name; the header is
	// set from the claim value. When the claim is missing from the JWT, the
	// header is removed from the request, even if the client sent a value.
	ForwardHeaders map[string]string `json:"forwardHeaders,omitempty" mapstructure:"forwardHeaders"`
	// ForwardIDTokenHeader, when set, forwards the raw ID token in that header.
	ForwardIDTokenHeader string `json:"forwardIDTokenHeader,omitempty" mapstructure:"forwardIDTokenHeader"`
	// ClientConfig tunes the HTTP client used to talk to the provider.
	ClientConfig *ClientConfig `json:"clientConfig,omitempty" mapstructure:"clientConfig"`
	// PKCE enables the Proof Key for Code Exchange (RFC 7636).
	PKCE bool `json:"pkce,omitempty" mapstructure:"pkce"`
	// DiscoveryParams are extra query parameters added to the well-known URI.
	DiscoveryParams map[string]string `json:"discoveryParams,omitempty" mapstructure:"discoveryParams"`
	// TrustedIssuer is the issuer value to validate in the tokens when the
	// discovery endpoint reports a different issuer.
	TrustedIssuer string `json:"trustedIssuer,omitempty" mapstructure:"trustedIssuer"`
	// DisableIssuerCheck disables the issuer validation in the JWT tokens.
	DisableIssuerCheck bool `json:"disableIssuerCheck,omitempty" mapstructure:"disableIssuerCheck"`
	// Scopes are the scopes requested from the provider. Must include "openid".
	Scopes []string `json:"scopes,omitempty" mapstructure:"scopes"`
	// AuthParams are extra query parameters passed to the provider's
	// authorization endpoint.
	AuthParams map[string]string `json:"authParams,omitempty" mapstructure:"authParams"`
	// DisableLogin disables the redirections to the provider: unauthorized
	// requests get a 401/403 instead of a login redirect.
	DisableLogin bool `json:"disableLogin,omitempty" mapstructure:"disableLogin"`
	// LoginURL starts the authorization flow when requested. All other
	// unauthorized requests get a 401.
	LoginURL string `json:"loginUrl,omitempty" mapstructure:"loginUrl"`
	// LogoutURL deletes the session.
	LogoutURL string `json:"logoutUrl,omitempty" mapstructure:"logoutUrl"`
	// PostLoginRedirectURL is where to redirect after a successful login.
	PostLoginRedirectURL string `json:"postLoginRedirectUrl,omitempty" mapstructure:"postLoginRedirectUrl"`
	// PostLogoutRedirectURL is where to redirect after a logout.
	PostLogoutRedirectURL string `json:"postLogoutRedirectUrl,omitempty" mapstructure:"postLogoutRedirectUrl"`
	// BackchannelLogoutURL is the URL the provider calls to log a user out
	// (OpenID Connect Back-Channel Logout).
	BackchannelLogoutURL string `json:"backchannelLogoutUrl,omitempty" mapstructure:"backchannelLogoutUrl"`
	// BackchannelLogoutSessionsRequired states whether the provider includes
	// the `sid` claim in the logout token.
	BackchannelLogoutSessionsRequired bool `json:"backchannelLogoutSessionsRequired,omitempty" mapstructure:"backchannelLogoutSessionsRequired"`

	// StateCookie configures the cookie binding an authorization flow to the
	// browser that started it.
	StateCookie *CookieConfig `json:"stateCookie,omitempty" mapstructure:"stateCookie"`
	// Session configures the session cookie and lifetime, including the
	// optional Redis session store.
	Session *SessionConfig `json:"session,omitempty" mapstructure:"session"`
	// Store configures the session store. The reference documents both
	// `store.keyPrefix` and `session.store.redis.*`; both spellings are
	// accepted here (see StoreConfig).
	Store *StoreConfig `json:"store,omitempty" mapstructure:"store"`
	// CSRF enables the CSRF protection (Signed Double Submit Cookie).
	CSRF *CSRFConfig `json:"csrf,omitempty" mapstructure:"csrf"`
}

// ClientConfig is the `clientConfig` section.
type ClientConfig struct {
	// TLS secures the connection to the authorization server.
	TLS *ClientTLSConfig `json:"tls,omitempty" mapstructure:"tls"`
	// TimeoutSeconds is the time before giving up a request to the provider.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty" mapstructure:"timeoutSeconds"`
	// MaxRetries is the number of retries for requests that fail.
	MaxRetries int `json:"maxRetries,omitempty" mapstructure:"maxRetries"`
}

// ClientTLSConfig is the `clientConfig.tls` section.
type ClientTLSConfig struct {
	CA                 string `json:"ca,omitempty" mapstructure:"ca"`
	Cert               string `json:"cert,omitempty" mapstructure:"cert"`
	Key                string `json:"key,omitempty" mapstructure:"key"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty" mapstructure:"insecureSkipVerify"`
}

// CookieConfig is the `stateCookie` section.
type CookieConfig struct {
	Name     string `json:"name,omitempty" mapstructure:"name"`
	Path     string `json:"path,omitempty" mapstructure:"path"`
	Domain   string `json:"domain,omitempty" mapstructure:"domain"`
	MaxAge   int    `json:"maxAge,omitempty" mapstructure:"maxAge"`
	SameSite string `json:"sameSite,omitempty" mapstructure:"sameSite"`
	HTTPOnly bool   `json:"httpOnly,omitempty" mapstructure:"httpOnly"`
	Secure   bool   `json:"secure,omitempty" mapstructure:"secure"`
}

// SessionConfig is the `session` section.
type SessionConfig struct {
	Name     string `json:"name,omitempty" mapstructure:"name"`
	Path     string `json:"path,omitempty" mapstructure:"path"`
	Domain   string `json:"domain,omitempty" mapstructure:"domain"`
	Expiry   int    `json:"expiry,omitempty" mapstructure:"expiry"`
	Sliding  bool   `json:"sliding,omitempty" mapstructure:"sliding"`
	Refresh  bool   `json:"refresh,omitempty" mapstructure:"refresh"`
	MaxAge   int    `json:"maxAge,omitempty" mapstructure:"maxAge"`
	SameSite string `json:"sameSite,omitempty" mapstructure:"sameSite"`
	HTTPOnly bool   `json:"httpOnly,omitempty" mapstructure:"httpOnly"`
	Secure   bool   `json:"secure,omitempty" mapstructure:"secure"`
	// Store is the nested `session.store` spelling of the session store.
	Store *StoreConfig `json:"store,omitempty" mapstructure:"store"`
}

// StoreConfig is the `store` (and `session.store`) section.
type StoreConfig struct {
	// KeyPrefix is the prefix of the keys used to store the sessions.
	KeyPrefix string `json:"keyPrefix,omitempty" mapstructure:"keyPrefix"`
	// Redis is the Redis session store.
	Redis *RedisStoreConfig `json:"redis,omitempty" mapstructure:"redis"`
}

// RedisStoreConfig is the `store.redis` (and `session.store.redis`) section.
type RedisStoreConfig struct {
	Endpoints []string `json:"endpoints,omitempty" mapstructure:"endpoints"`
	Username  string   `json:"username,omitempty" mapstructure:"username"`
	Password  string   `json:"password,omitempty" mapstructure:"password"`
	Database  int      `json:"database,omitempty" mapstructure:"database"`
	// Cluster enables the Redis Cluster topology. It is the single Hub option
	// this plugin does not implement: setting it is an error.
	Cluster string `json:"cluster,omitempty" mapstructure:"cluster"`
	// TLS secures the connections to Redis (and to the Sentinels).
	TLS *RedisTLSConfig `json:"tls,omitempty" mapstructure:"tls"`
	// Sentinel enables the Redis Sentinel topology.
	Sentinel *SentinelConfig `json:"sentinel,omitempty" mapstructure:"sentinel"`
}

// RedisTLSConfig is the `store.redis.tls` section.
type RedisTLSConfig struct {
	CABundle           string `json:"caBundle,omitempty" mapstructure:"caBundle"`
	Cert               string `json:"cert,omitempty" mapstructure:"cert"`
	Key                string `json:"key,omitempty" mapstructure:"key"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty" mapstructure:"insecureSkipVerify"`
}

// SentinelConfig is the `store.redis.sentinel` section.
type SentinelConfig struct {
	MasterSet string `json:"masterSet,omitempty" mapstructure:"masterSet"`
	Username  string `json:"username,omitempty" mapstructure:"username"`
	Password  string `json:"password,omitempty" mapstructure:"password"`
}

// CSRFConfig is the `csrf` section.
type CSRFConfig struct {
	// Secure restricts the CSRF cookie to HTTPS requests.
	Secure bool `json:"secure,omitempty" mapstructure:"secure"`
	// HeaderName is the header carrying the CSRF token.
	HeaderName string `json:"headerName,omitempty" mapstructure:"headerName"`
}

// HeaderTemplate is one entry of the `headers` extension.
type HeaderTemplate struct {
	Name        string `json:"name,omitempty" mapstructure:"name"`
	Value       string `json:"value,omitempty" mapstructure:"value"`
	Values      string `json:"values,omitempty" mapstructure:"values"`
	IncludeWhen string `json:"includeWhen,omitempty" mapstructure:"includeWhen"`
}

// Default returns a configuration populated with the documented defaults.
// Traefik overlays the user configuration on top of it, so a field that is
// left out keeps its default. Boolean options defaulting to true (session
// sliding, session refresh) are the reason this is not a zero value.
func Default() *Config {
	return &Config{
		ClientConfig: &ClientConfig{
			TimeoutSeconds: 5,
			MaxRetries:     3,
		},
		Scopes: []string{"openid"},
		StateCookie: &CookieConfig{
			Path:     "/",
			MaxAge:   600,
			SameSite: "lax",
			HTTPOnly: true,
			Secure:   false,
		},
		Session: &SessionConfig{
			Path:     "/",
			Expiry:   86400,
			Sliding:  true,
			Refresh:  true,
			SameSite: "lax",
			HTTPOnly: true,
			Secure:   false,
		},
		// CSRF is disabled by default (nil): the reference documents its
		// default as "" (unset). Setting the header name here would enable it
		// for every configuration.
	}
}
