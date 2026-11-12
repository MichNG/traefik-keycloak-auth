package config

import (
	"text/template"

	"github.com/MichNG/traefik-keycloak-auth/internal/claims"
	"github.com/MichNG/traefik-keycloak-auth/internal/errorPages"
)

const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

const (
	SessionStorageTypeCookie string = "Cookie"
	SessionStorageTypeRedis  string = "Redis"
)

type Config struct {
	LogLevel string `json:"log_level"`

	Secret string `json:"secret"`

	Provider *ProviderConfig `json:"provider"`
	Scopes   []string        `json:"scopes"`

	// Can be a relative path or a full URL.
	// If a relative path is used, the scheme and domain will be taken from the incoming request.
	// In this case, the callback path will overlay all hostnames behind the middleware.
	// If a full URL is used, all callbacks are sent there.  It is the user's responsibility to ensure
	// that the callback URL is also routed to this middleware plugin.
	CallbackUri string `json:"callback_uri"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri                    string   `json:"login_uri"`
	PostLoginRedirectUri        string   `json:"post_login_redirect_uri"`
	ValidPostLoginRedirectUris  []string `json:"valid_post_login_redirect_uris"`
	LogoutUri                   string   `json:"logout_uri"`
	PostLogoutRedirectUri       string   `json:"post_logout_redirect_uri"`
	ValidPostLogoutRedirectUris []string `json:"valid_post_logout_redirect_uris"`

	SessionStorageType string `json:"session_storage_type"`

	CookieNamePrefix        string                     `json:"cookie_name_prefix"`
	SessionCookie           *SessionCookieConfig       `json:"session_cookie"`
	AuthorizationHeader     *AuthorizationHeaderConfig `json:"authorization_header"`
	AuthorizationCookie     *AuthorizationCookieConfig `json:"authorization_cookie"`
	UnauthenticatedBehavior string                     `json:"unauthenticated_behavior"`
	UnauthorizedBehavior    string                     `json:"unauthorized_behavior"`

	Authorization *AuthorizationConfig `json:"authorization"`

	Headers []HeaderConfig `json:"headers"`

	BypassAuthenticationRule string `json:"bypass_authentication_rule"`

	ErrorPages *errorPages.ErrorPagesConfig `json:"error_pages"`

	RequestedResources []string `json:"requested_resources"`

	// Additional query parameters to send to the IDP's authorization endpoint, eg. acr_values or prompt.
	// A `prompt` query parameter on the incoming /login request still takes precedence over this.
	AuthorizationParams map[string]string `json:"authorization_params"`

	// ------------------------------------------------------------------
	// Fields added by this fork to implement the Traefik Hub OIDC schema.
	// ------------------------------------------------------------------

	// ForwardHeaders maps a header name to a claim name (`forwardHeaders`).
	ForwardHeaders []ForwardHeader `json:"forward_headers"`
	// ForwardIDTokenHeader forwards the raw ID token in that header.
	ForwardIDTokenHeader string `json:"forward_id_token_header"`
	// ForwardAccessToken injects `Authorization: Bearer <access_token>`.
	ForwardAccessToken bool `json:"forward_access_token"`
	// AllowRedirectUriWildcards enables the `*` wildcard for this middleware.
	AllowRedirectUriWildcards bool `json:"allow_redirect_uri_wildcards"`
	// UsernameClaim is logged as the end-user name (`usernameClaim`).
	UsernameClaim string `json:"username_claim"`
	// IdentityClaim is the claim identifying the caller (`identity`).
	IdentityClaim string `json:"identity_claim"`

	// SessionExpiry is the session lifetime in seconds (`session.expiry`).
	SessionExpiry int `json:"session_expiry"`
	// SessionSliding renews the session cookie on every authenticated request
	// (`session.sliding`).
	SessionSliding bool `json:"session_sliding"`
	// SessionRefresh enables the access token refresh (`session.refresh`).
	SessionRefresh bool `json:"session_refresh"`
	// SessionMaxAge bounds the end-user authentication itself, in seconds
	// (`session.maxAge`). 0 disables it.
	SessionMaxAge int `json:"session_max_age"`
	// SessionCookieName overrides the session cookie name (`session.name`).
	SessionCookieName string `json:"session_cookie_name"`

	// StateCookie holds the settings of the browser-binding cookie
	// (`stateCookie.*`).
	StateCookie *SessionCookieConfig `json:"state_cookie"`
	// StateCookieName overrides the browser-binding cookie name
	// (`stateCookie.name`).
	StateCookieName string `json:"state_cookie_name"`

	// CSRF enables the CSRF protection (`csrf`).
	CSRF *CSRFConfig `json:"csrf"`
	// BackchannelLogout enables the OIDC back-channel logout endpoint.
	BackchannelLogout *BackchannelLogoutConfig `json:"backchannel_logout"`
}

// ForwardHeader maps an HTTP header to a claim.
type ForwardHeader struct {
	Name  string `json:"name"`
	Claim string `json:"claim"`
}

// CSRFConfig is the internal form of the `csrf` section.
type CSRFConfig struct {
	Enabled    bool   `json:"enabled"`
	Secure     bool   `json:"secure"`
	HeaderName string `json:"header_name"`
}

// BackchannelLogoutConfig is the internal form of the `backchannelLogout*`
// options.
type BackchannelLogoutConfig struct {
	Enabled          bool   `json:"enabled"`
	Path             string `json:"path"`
	SessionsRequired bool   `json:"sessions_required"`
}

type ProviderConfig struct {
	Url string `json:"url"`

	InsecureSkipVerify     string `json:"insecure_skip_verify"`
	InsecureSkipVerifyBool bool   `json:"insecure_skip_verify_bool"`

	CABundle     string `json:"ca_bundle"`
	CABundleFile string `json:"ca_bundle_file"`

	// ClientCert and ClientKey enable mTLS towards the authorization server
	// (`clientConfig.tls.cert` / `.key`).
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`

	// DiscoveryParams are extra query parameters of the well-known URL
	// (`discoveryParams`).
	DiscoveryParams map[string]string `json:"discovery_params"`
	// TrustedIssuer is the issuer validated in the tokens when it differs from
	// the discovery `issuer` (`trustedIssuer`).
	TrustedIssuer string `json:"trusted_issuer"`
	// TimeoutSeconds and MaxRetries tune the HTTP client (`clientConfig.*`).
	TimeoutSeconds int `json:"timeout_seconds"`
	MaxRetries     int `json:"max_retries"`

	ClientId              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientJwtPrivateKey   string `json:"client_jwt_private_key"`
	ClientJwtPrivateKeyId string `json:"client_jwt_private_key_id"`

	UsePkce     string `json:"use_pkce"`
	UsePkceBool bool   `json:"use_pkce_bool"`

	ValidateAudience     string `json:"validate_audience"`
	ValidateAudienceBool bool   `json:"validate_audience_bool"`
	ValidAudience        string `json:"valid_audience"`

	ValidateIssuer     string `json:"validate_issuer"`
	ValidateIssuerBool bool   `json:"validate_issuer_bool"`
	ValidIssuer        string `json:"valid_issuer"`

	// AccessToken or IdToken or Introspection
	TokenValidation string `json:"verification_token"`

	TokenRenewalThreshold float64 `json:"token_renewal_threshold"`

	UseClaimsFromUserInfo     string `json:"use_claims_from_user_info"`
	UseClaimsFromUserInfoBool bool   `json:"use_claims_from_user_info_bool"`
}

type SessionCookieConfig struct {
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
	MaxAge   int    `json:"max_age"`
}

type AuthorizationHeaderConfig struct {
	Name string `json:"name"`
}
type AuthorizationCookieConfig struct {
	Name string `json:"name"`
}

type AuthorizationConfig struct {
	AssertClaims        []ClaimAssertion `json:"assert_claims"`
	CheckOnEveryRequest bool             `json:"check_on_every_request"`

	// Expr is the parsed Hub `claims` expression. When set it takes precedence
	// over AssertClaims.
	Expr *claims.Expr `json:"-"`
}

type ClaimAssertion struct {
	Name  string   `json:"name"`
	AnyOf []string `json:"anyOf"`
	AllOf []string `json:"allOf"`
}

type HeaderConfig struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Values      string `json:"values"`
	IncludeWhen string `json:"include_when"`

	// A reference to the parsed Value-template
	Template *template.Template
}
