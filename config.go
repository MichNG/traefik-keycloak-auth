package traefik_keycloak_auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/csrf"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/rules"
	"github.com/MichNG/traefik-keycloak-auth/internal/session"
	"github.com/MichNG/traefik-keycloak-auth/internal/utils"
	"github.com/MichNG/traefik-keycloak-auth/internalconfig"
)

// CreateConfig is called by Traefik to obtain the configuration schema of the
// plugin. It returns the Hub-shaped configuration, populated with the
// documented defaults.
func CreateConfig() *internalconfig.Config {
	return internalconfig.Default()
}

// New is called by Traefik to build the middleware handler.
func New(uctx context.Context, next http.Handler, hubCfg *internalconfig.Config, name string) (http.Handler, error) {
	adapted, err := internalconfig.Adapt(hubCfg)
	if err != nil {
		return nil, err
	}

	cfg := adapted.Config
	cfg.LogLevel = utils.ExpandEnvironmentVariableString(cfg.LogLevel)

	logger := logging.CreateLogger(cfg.LogLevel)

	logger.Log(logging.LevelInfo, "Loading Configuration...")

	if cfg.Provider == nil {
		return nil, errors.New("missing provider configuration")
	}

	cfg.Secret = utils.ExpandEnvironmentVariableString(cfg.Secret)
	cfg.CallbackUri = utils.ExpandEnvironmentVariableString(cfg.CallbackUri)
	cfg.LoginUri = utils.ExpandEnvironmentVariableString(cfg.LoginUri)
	cfg.PostLoginRedirectUri = utils.ExpandEnvironmentVariableString(cfg.PostLoginRedirectUri)
	cfg.LogoutUri = utils.ExpandEnvironmentVariableString(cfg.LogoutUri)
	cfg.PostLogoutRedirectUri = utils.ExpandEnvironmentVariableString(cfg.PostLogoutRedirectUri)
	cfg.BypassAuthenticationRule = utils.ExpandEnvironmentVariableString(cfg.BypassAuthenticationRule)
	cfg.Provider.Url = utils.ExpandEnvironmentVariableString(cfg.Provider.Url)
	cfg.Provider.ClientId = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientId)
	cfg.Provider.ClientSecret = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientSecret)
	cfg.Provider.ClientJwtPrivateKeyId = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientJwtPrivateKeyId)
	cfg.Provider.ClientJwtPrivateKey = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientJwtPrivateKey)
	cfg.Provider.UsePkceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.UsePkce, cfg.Provider.UsePkceBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.UseClaimsFromUserInfoBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.UseClaimsFromUserInfo, cfg.Provider.UseClaimsFromUserInfoBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidateIssuerBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateIssuer, cfg.Provider.ValidateIssuerBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidIssuer = utils.ExpandEnvironmentVariableString(cfg.Provider.ValidIssuer)
	cfg.Provider.ValidateAudienceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateAudience, cfg.Provider.ValidateAudienceBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidAudience = utils.ExpandEnvironmentVariableString(cfg.Provider.ValidAudience)
	cfg.Provider.InsecureSkipVerifyBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.InsecureSkipVerify, cfg.Provider.InsecureSkipVerifyBool)
	if err != nil {
		return nil, err
	}

	var clientAssertionPrivateKey *rsa.PrivateKey
	if cfg.Provider.ClientJwtPrivateKey != "" && cfg.Provider.ClientJwtPrivateKeyId != "" {
		clientAssertionPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.Provider.ClientJwtPrivateKey))
		if err != nil {
			return nil, err
		}
	}

	cfg.Provider.CABundle = utils.ExpandEnvironmentVariableString(cfg.Provider.CABundle)
	cfg.Provider.CABundleFile = utils.ExpandEnvironmentVariableString(cfg.Provider.CABundleFile)
	cfg.Provider.TokenValidation = utils.ExpandEnvironmentVariableString(cfg.Provider.TokenValidation)

	cfg.ErrorPages.Unauthenticated.FilePath = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthenticated.FilePath)
	cfg.ErrorPages.Unauthenticated.RedirectTo = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthenticated.RedirectTo)
	cfg.ErrorPages.Unauthorized.FilePath = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthorized.FilePath)
	cfg.ErrorPages.Unauthorized.RedirectTo = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthorized.RedirectTo)

	if cfg.Secret == config.DefaultSecret {
		logger.Log(logging.LevelWarn, "You're using the default secret! It is highly recommended to change the secret by specifying a random 32 character value using the Secret-option.")
	}

	secret := []byte(cfg.Secret)
	if len(secret) != 32 {
		logger.Log(logging.LevelError, "Invalid secret provided. Secret must be exactly 32 characters in length. The provided secret has %d characters.", len(secret))
		return nil, errors.New("invalid secret")
	}

	if cfg.Provider.CABundle != "" && cfg.Provider.CABundleFile != "" {
		logger.Log(logging.LevelError, "You can only use an inline CABundle OR CABundleFile, not both.")
		return nil, errors.New("you can only use an inline CABundle OR CABundleFile, not both.")
	}

	// Specify default scopes if not provided
	if cfg.Scopes == nil || len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	parsedURL, err := utils.ParseUrl(cfg.Provider.Url)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing issuer: %s", err.Error())
		return nil, err
	}

	parsedCallbackURL, err := utils.ParseUrl(cfg.CallbackUri)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing redirectUrl: %s", err.Error())
		return nil, err
	}
	// RedirectURLs are resolved against the request, so only the path matters
	// for the relative form. ParseUrl handles both.
	parsedCallbackURL.Path = pathOf(parsedCallbackURL)

	if cfg.CallbackUri != "" && !utils.UrlIsAbsolute(parsedCallbackURL) {
		parsedCallbackURL.Scheme = ""
		parsedCallbackURL.Host = ""
	}

	logger.Log(logging.LevelInfo, "Provider Url: %v", parsedURL)
	logger.Log(logging.LevelInfo, "I will use this URL for callbacks from the IDP: %v", parsedCallbackURL)
	if utils.UrlIsAbsolute(parsedCallbackURL) {
		logger.Log(logging.LevelInfo, "Callback URL is absolute, will not overlay wrapped services")
	} else {
		logger.Log(logging.LevelInfo, "Callback URL is relative, will overlay any wrapped host")
	}
	logger.Log(logging.LevelDebug, "Scopes: %s", strings.Join(cfg.Scopes, ", "))

	switch cfg.Provider.TokenValidation {
	case "AccessToken", "IdToken", "Introspection":
	default:
		logger.Log(logging.LevelError, "Invalid TokenValidation \"%s\". Must be one of AccessToken, IdToken or Introspection.", cfg.Provider.TokenValidation)
		return nil, fmt.Errorf("invalid tokenValidation %q: must be one of IdToken, AccessToken or Introspection", cfg.Provider.TokenValidation)
	}

	if cfg.Provider.TokenRenewalThreshold < 0.5 || cfg.Provider.TokenRenewalThreshold > 1.0 {
		logger.Log(logging.LevelError, "Invalid TokenRenewalThreshold. The value must be >= 0.5 and <= 1.0.")
		return nil, fmt.Errorf("invalid tokenRenewalThreshold %v: must be >= 0.5 and <= 1.0", cfg.Provider.TokenRenewalThreshold)
	}

	// Cookie names: the Hub reference derives them from the middleware name.
	defaultCookiePrefix(cfg, name)
	logger.Log(logging.LevelDebug, "Session cookie: %v", cfg.SessionCookie)

	var conditionalAuth *rules.RequestCondition
	if cfg.BypassAuthenticationRule != "" {
		ca, err := rules.ParseRequestCondition(cfg.BypassAuthenticationRule)
		if err != nil {
			return nil, err
		}
		conditionalAuth = ca
	}

	for i := range cfg.Headers {
		header := &cfg.Headers[i]

		if header.Value != "" && header.Values != "" {
			logger.Log(logging.LevelError, "Invalid Header: you can only use one of Value or Values, not both")
			return nil, errors.New("invalid Header")
		}

		templateSource := header.Value
		if templateSource == "" {
			templateSource = header.Values
		}
		if templateSource == "" {
			continue
		}

		tpl, err := newTemplate().Parse(templateSource)
		if err != nil {
			logger.Log(logging.LevelError, "Invalid template for header %s: %s", header.Name, err.Error())
			return nil, err
		}

		header.Template = tpl
	}

	// Per the OIDC/OAuth2 spec a redirect uri must match exactly. Wildcard matching is an
	// explicit opt-in via this env var rather than a normal config option, since it's a
	// security-relevant choice meant to be made once for the whole Traefik instance.
	redirectUriWildcardsEnabled, err := utils.ExpandEnvironmentVariableBoolean(os.Getenv("TOA_ENABLE_REDIRECT_URI_WILDCARDS"), false)
	if err != nil {
		logger.Log(logging.LevelError, "Invalid TOA_ENABLE_REDIRECT_URI_WILDCARDS value: %s", err.Error())
		return nil, err
	}

	// The wildcard can also be enabled for this middleware only, instead of
	// for the whole Traefik process.
	if cfg.AllowRedirectUriWildcards {
		redirectUriWildcardsEnabled = true
	}

	if redirectUriWildcardsEnabled {
		logger.Log(logging.LevelWarn, "Redirect-URI wildcard matching is ENABLED: a configured `*` will accept any redirect URI for this middleware. Prefer explicit URIs.")
	}

	if !redirectUriWildcardsEnabled {
		for _, uri := range cfg.ValidPostLoginRedirectUris {
			if strings.Contains(uri, "*") {
				logger.Log(logging.LevelWarn, "ValidPostLoginRedirectUris contains %q, which looks like it's meant to be a wildcard, but TOA_ENABLE_REDIRECT_URI_WILDCARDS is not set -- it will only match this exact string.", uri)
			}
		}
		for _, uri := range cfg.ValidPostLogoutRedirectUris {
			if strings.Contains(uri, "*") {
				logger.Log(logging.LevelWarn, "ValidPostLogoutRedirectUris contains %q, which looks like it's meant to be a wildcard, but TOA_ENABLE_REDIRECT_URI_WILDCARDS is not set -- it will only match this exact string.", uri)
			}
		}
	}

	httpClient, err := newHTTPClient(cfg, logger)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to build the HTTP client: %s", err.Error())
		return nil, err
	}

	var storage session.SessionStorage
	var revoker session.Revoker

	if adapted.Redis != nil {
		if adapted.Redis.KeyPrefix == "" {
			// Isolate the keys of each middleware instance by default, so two
			// OIDC middlewares sharing one Redis database cannot revoke each
			// other's sessions through the sid/sub indexes.
			adapted.Redis.KeyPrefix = sanitizeCookieToken(name) + ":"
		}

		redisStorage, err := session.CreateRedisSessionStorage(uctx, logger, *adapted.Redis)
		if err != nil {
			logger.Log(logging.LevelError, "Failed to configure the Redis session store: %s", err.Error())
			return nil, err
		}
		storage = redisStorage
		revoker = redisStorage
	} else {
		storage = session.CreateCookieSessionStorage()
	}

	var csrfProtector *csrf.Protector
	if cfg.CSRF != nil && cfg.CSRF.Enabled {
		csrfProtector = csrf.New(cfg.Secret, time.Duration(cfg.SessionExpiry)*time.Second)
		logger.Log(logging.LevelInfo, "CSRF protection enabled (header %q)", cfg.CSRF.HeaderName)
	}

	logger.Log(logging.LevelInfo, "Configuration loaded successfully, starting OIDC Auth middleware...")

	return &TraefikOidcAuth{
		logger:                      logger,
		next:                        next,
		httpClient:                  httpClient,
		ProviderURL:                 parsedURL,
		ClientJwtPrivateKey:         clientAssertionPrivateKey,
		CallbackURL:                 parsedCallbackURL,
		Config:                      cfg,
		SessionStorage:              storage,
		Revoker:                     revoker,
		CSRF:                        csrfProtector,
		BypassAuthenticationRule:    conditionalAuth,
		RedirectUriWildcardsEnabled: redirectUriWildcardsEnabled,
	}, nil
}

// defaultCookiePrefix fills the cookie names the Hub reference derives from the
// middleware name (stateCookie.name / session.name default to
// "MIDDLEWARE_NAME-state" / "MIDDLEWARE_NAME-session").
func defaultCookiePrefix(cfg *config.Config, name string) {
	middleware := sanitizeCookieToken(name)
	if middleware == "" {
		middleware = "traefik-keycloak-auth"
	}

	if cfg.CookieNamePrefix == "" {
		cfg.CookieNamePrefix = middleware
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = middleware + "-session"
	}
	if cfg.StateCookieName == "" {
		cfg.StateCookieName = middleware + "-state"
	}
}

// sanitizeCookieToken keeps only the characters allowed in a cookie name.
func sanitizeCookieToken(value string) string {
	var sb strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			sb.WriteRune(r)
		default:
			sb.WriteRune('-')
		}
	}
	return strings.Trim(sb.String(), "-")
}

// pathOf returns the path of a parsed URL (possibly empty).
func pathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}

// defaultStateCookie is the fallback state cookie, matching `stateCookie.*`
// defaults, used when an older configuration left StateCookie unset.
func defaultStateCookie() *config.SessionCookieConfig {
	return &config.SessionCookieConfig{
		Path:     "/",
		HttpOnly: true,
		SameSite: "lax",
		MaxAge:   600,
	}
}
