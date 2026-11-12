package internalconfig

// Adapter: translates the public Hub-shaped configuration into the internal
// configuration used by the middleware, plus the options of the Redis session
// store when one is configured.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/claims"
	pluginconfig "github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/errorPages"
	"github.com/MichNG/traefik-keycloak-auth/internal/session"
	"github.com/MichNG/traefik-keycloak-auth/internal/utils"
)

// Adapted is the result of Adapt.
type Adapted struct {
	// Config is the internal middleware configuration.
	Config *pluginconfig.Config
	// Redis is the session store configuration, nil when the sessions are kept
	// in the cookie (the default).
	Redis *session.RedisOptions
	// Claims is the parsed authorization expression, nil when `claims` is unset.
	Claims *claims.Expr
}

// Adapt validates the public configuration and maps it to the internal one.
//
// It returns an error for the options that cannot be honoured: a missing
// required option and the single Hub option this plugin does not implement,
// `session.store.redis.cluster` (Enable Redis Cluster).
func Adapt(h *Config) (*Adapted, error) {
	if h == nil {
		return nil, errors.New("missing configuration")
	}

	var missing []string
	if strings.TrimSpace(h.Issuer) == "" {
		missing = append(missing, "issuer")
	}
	if strings.TrimSpace(h.RedirectURL) == "" {
		missing = append(missing, "redirectUrl")
	}
	if strings.TrimSpace(h.ClientID) == "" {
		missing = append(missing, "clientID")
	}
	if strings.TrimSpace(h.ClientSecret) == "" {
		missing = append(missing, "clientSecret")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required option(s): %s", strings.Join(missing, ", "))
	}

	cfg := &pluginconfig.Config{
		LogLevel:            orDefault(h.LogLevel, "WARN"),
		Secret:              h.Secret,
		Provider:            &pluginconfig.ProviderConfig{},
		Scopes:              h.Scopes,
		CallbackUri:         h.RedirectURL,
		LoginUri:            h.LoginURL,
		LogoutUri:           h.LogoutURL,
		SessionCookie:       &pluginconfig.SessionCookieConfig{},
		AuthorizationHeader: &pluginconfig.AuthorizationHeaderConfig{},
		AuthorizationCookie: &pluginconfig.AuthorizationCookieConfig{},
		Authorization: &pluginconfig.AuthorizationConfig{
			// The claims are re-evaluated on every request: a session that
			// outlives a role revocation must not stay authorized.
			CheckOnEveryRequest: true,
		},
		ErrorPages: &errorPages.ErrorPagesConfig{
			Unauthenticated: &errorPages.ErrorPageConfig{},
			Unauthorized:    &errorPages.ErrorPageConfig{},
		},
	}

	if cfg.Secret == "" {
		cfg.Secret = DefaultSecret
	}
	cfg.Secret = utils.ExpandEnvironmentVariableString(cfg.Secret)

	// The state and session encryption require a 32 character key.
	if len(cfg.Secret) != 32 {
		return nil, fmt.Errorf("secret must be exactly 32 characters long (the provided secret has %d)", len(cfg.Secret))
	}

	provider := cfg.Provider
	provider.Url = expand(h.Issuer)
	provider.ClientId = expand(h.ClientID)
	provider.ClientSecret = expand(h.ClientSecret)
	provider.UsePkceBool = h.PKCE
	provider.DiscoveryParams = expandMap(h.DiscoveryParams)
	provider.TrustedIssuer = expand(h.TrustedIssuer)
	provider.ValidIssuer = provider.TrustedIssuer
	provider.ValidateIssuerBool = !h.DisableIssuerCheck
	// Audience validation is always on, like the community plugin default.
	provider.ValidateAudienceBool = true
	provider.TokenValidation = orDefault(h.TokenValidation, "IdToken")
	provider.TokenRenewalThreshold = h.TokenRenewalThreshold
	if provider.TokenRenewalThreshold == 0 {
		provider.TokenRenewalThreshold = 0.75
	}
	provider.UseClaimsFromUserInfoBool = h.UseClaimsFromUserInfo

	if h.ClientConfig != nil {
		provider.TimeoutSeconds = h.ClientConfig.TimeoutSeconds
		provider.MaxRetries = h.ClientConfig.MaxRetries
		if tls := h.ClientConfig.TLS; tls != nil {
			provider.InsecureSkipVerifyBool = tls.InsecureSkipVerify
			provider.CABundle = expand(tls.CA)
			provider.ClientCert = expand(tls.Cert)
			provider.ClientKey = expand(tls.Key)
		}
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid"}
	}

	// redirectUrl resolution: absolute, or relative to the request.
	if _, err := utils.ParseUrl(cfg.CallbackUri); err != nil {
		return nil, fmt.Errorf("invalid redirectUrl %q: %w", cfg.CallbackUri, err)
	}
	cfg.CallbackUri = expand(cfg.CallbackUri)
	cfg.PostLoginRedirectUri = expand(h.PostLoginRedirectURL)
	cfg.PostLogoutRedirectUri = expand(h.PostLogoutRedirectURL)
	cfg.LoginUri = expand(cfg.LoginUri)
	cfg.LogoutUri = expand(cfg.LogoutUri)
	cfg.AuthorizationParams = expandMap(h.AuthParams)

	// disableLogin: never redirect to the provider.
	if h.DisableLogin {
		cfg.UnauthenticatedBehavior = "Unauthorized"
		cfg.UnauthorizedBehavior = "Unauthorized"
	} else {
		cfg.UnauthenticatedBehavior = "Auto"
		cfg.UnauthorizedBehavior = "Unauthorized"
	}

	// Claims expression.
	if strings.TrimSpace(h.Claims) != "" {
		expr, err := claims.Parse(h.Claims)
		if err != nil {
			return nil, err
		}
		cfg.Authorization.Expr = expr
	}

	cfg.UsernameClaim = h.UsernameClaim
	// Hub defaults `identity` to the `sub` claim.
	cfg.IdentityClaim = orDefault(h.Identity, "sub")
	cfg.ForwardIDTokenHeader = h.ForwardIDTokenHeader
	cfg.ForwardAccessToken = h.ForwardAccessToken
	cfg.AllowRedirectUriWildcards = h.AllowRedirectUriWildcards
	for _, header := range h.Headers {
		if strings.TrimSpace(header.Name) == "" {
			return nil, errors.New("headers contains an entry without a name")
		}
		cfg.Headers = append(cfg.Headers, pluginconfig.HeaderConfig{
			Name:        header.Name,
			Value:       header.Value,
			Values:      header.Values,
			IncludeWhen: header.IncludeWhen,
		})
	}
	for header, claim := range h.ForwardHeaders {
		if strings.TrimSpace(header) == "" || strings.TrimSpace(claim) == "" {
			return nil, fmt.Errorf("forwardHeaders contains an empty header or claim (%q: %q)", header, claim)
		}
		cfg.ForwardHeaders = append(cfg.ForwardHeaders, pluginconfig.ForwardHeader{Name: header, Claim: claim})
	}

	// Session cookie and lifetime.
	sessName, sessPath, sessDomain, sessSameSite := "", "/", "", "lax"
	sessHTTPOnly, sessSecure := true, false
	sessExpiry := 86400
	sessSliding, sessRefresh, sessMaxAge := true, true, 0
	if s := h.Session; s != nil {
		sessName = s.Name
		if s.Path != "" {
			sessPath = s.Path
		}
		sessDomain = s.Domain
		if s.SameSite != "" {
			sessSameSite = s.SameSite
		}
		sessHTTPOnly = s.HTTPOnly
		sessSecure = s.Secure
		sessExpiry = s.Expiry
		sessSliding = s.Sliding
		sessRefresh = s.Refresh
		sessMaxAge = s.MaxAge
	}
	if sessExpiry <= 0 {
		return nil, errors.New("session.expiry must be > 0")
	}
	if sessMaxAge < 0 {
		return nil, errors.New("session.maxAge must be > 0 when set")
	}

	cfg.SessionCookieName = sessName
	cfg.SessionCookie.Path = sessPath
	cfg.SessionCookie.Domain = sessDomain
	cfg.SessionCookie.SameSite = sessSameSite
	cfg.SessionCookie.HttpOnly = sessHTTPOnly
	cfg.SessionCookie.Secure = sessSecure
	cfg.SessionCookie.MaxAge = sessExpiry
	cfg.SessionExpiry = sessExpiry
	cfg.SessionSliding = sessSliding
	cfg.SessionRefresh = sessRefresh
	cfg.SessionMaxAge = sessMaxAge

	// State cookie (browser binding).
	statePath, stateSameSite := "/", "lax"
	stateHTTPOnly, stateSecure, stateMaxAge := true, false, 600
	stateName, stateDomain := "", ""
	if s := h.StateCookie; s != nil {
		stateName = s.Name
		if s.Path != "" {
			statePath = s.Path
		}
		stateDomain = s.Domain
		if s.SameSite != "" {
			stateSameSite = s.SameSite
		}
		stateHTTPOnly = s.HTTPOnly
		stateSecure = s.Secure
		// A zero maxAge expires the cookie immediately (the reference
		// documents it); it must not be confused with "not set", which is
		// already represented by the default value of 600.
		stateMaxAge = s.MaxAge
		if stateMaxAge == 0 {
			stateMaxAge = -1
		}
	}
	cfg.StateCookieName = stateName
	cfg.StateCookie = &pluginconfig.SessionCookieConfig{
		Path:     statePath,
		Domain:   stateDomain,
		SameSite: stateSameSite,
		HttpOnly: stateHTTPOnly,
		Secure:   stateSecure,
		MaxAge:   stateMaxAge,
	}

	// CSRF.
	if h.CSRF != nil {
		headerName := h.CSRF.HeaderName
		if headerName == "" {
			headerName = "Hub-Csrf-Token"
		}
		cfg.CSRF = &pluginconfig.CSRFConfig{
			Enabled:    true,
			Secure:     h.CSRF.Secure,
			HeaderName: headerName,
		}
	}

	// Back-channel logout.
	if h.BackchannelLogoutURL != "" {
		u, err := url.Parse(h.BackchannelLogoutURL)
		if err != nil || u.Path == "" {
			return nil, fmt.Errorf("invalid backchannelLogoutUrl %q", h.BackchannelLogoutURL)
		}
		cfg.BackchannelLogout = &pluginconfig.BackchannelLogoutConfig{
			Enabled:          true,
			Path:             u.Path,
			SessionsRequired: h.BackchannelLogoutSessionsRequired,
		}
	}

	// Session store.
	store, redisCfg, err := resolveStore(h)
	if err != nil {
		return nil, err
	}

	if redisCfg == nil {
		cfg.SessionStorageType = pluginconfig.SessionStorageTypeCookie
		return &Adapted{Config: cfg, Claims: cfg.Authorization.Expr}, nil
	}

	if strings.TrimSpace(redisCfg.Cluster) != "" {
		return nil, errors.New("session.store.redis.cluster (\"Enable Redis Cluster\") is not supported by this plugin; use endpoints or Sentinel instead")
	}

	ttl := time.Duration(sessExpiry) * time.Second

	opts := &session.RedisOptions{
		Endpoints: redisCfg.Endpoints,
		Username:  expand(redisCfg.Username),
		Password:  expand(redisCfg.Password),
		Database:  redisCfg.Database,
		KeyPrefix: store.KeyPrefix,
		TTL:       ttl,
		Secret:    cfg.Secret,
		Timeout:   2 * time.Second,
	}
	if redisCfg.TLS != nil {
		opts.TLS = &session.RedisTLS{
			CABundle:           expand(redisCfg.TLS.CABundle),
			Cert:               expand(redisCfg.TLS.Cert),
			Key:                expand(redisCfg.TLS.Key),
			InsecureSkipVerify: redisCfg.TLS.InsecureSkipVerify,
		}
	}
	if redisCfg.Sentinel != nil {
		opts.Sentinel = &session.RedisSentinel{
			MasterSet: redisCfg.Sentinel.MasterSet,
			Username:  expand(redisCfg.Sentinel.Username),
			Password:  expand(redisCfg.Sentinel.Password),
		}
	}

	cfg.SessionStorageType = pluginconfig.SessionStorageTypeRedis

	return &Adapted{Config: cfg, Redis: opts, Claims: cfg.Authorization.Expr}, nil
}

// resolveStore accepts the two documented spellings of the session store
// (`store.redis.*` and `session.store.redis.*`). `session.store` wins when
// both are present; the key prefix is taken from the first one that sets it.
func resolveStore(h *Config) (StoreConfig, *RedisStoreConfig, error) {
	var store StoreConfig

	if h.Store != nil {
		store = *h.Store
	}

	if h.Session != nil && h.Session.Store != nil {
		nested := *h.Session.Store
		if nested.Redis != nil {
			store.Redis = nested.Redis
		}
		if nested.KeyPrefix != "" {
			store.KeyPrefix = nested.KeyPrefix
		}
	}

	return store, store.Redis, nil
}

// GetKeyPrefix returns the key prefix or the default one.
func (s StoreConfig) GetKeyPrefix() string {
	if s.KeyPrefix == "" {
		return session.DefaultKeyPrefix
	}
	return s.KeyPrefix
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func expand(value string) string {
	return utils.ExpandEnvironmentVariableString(strings.TrimSpace(value))
}

func expandMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = utils.ExpandEnvironmentVariableString(v)
	}
	return out
}
