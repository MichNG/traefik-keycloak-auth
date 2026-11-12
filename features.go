package traefik_keycloak_auth

// Hub-schema features wired into the middleware: discovery parameters,
// forward headers, CSRF, back-channel logout and the claims expression.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MichNG/traefik-keycloak-auth/internal/claims"
	"github.com/MichNG/traefik-keycloak-auth/internal/csrf"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/session"
	"github.com/MichNG/traefik-keycloak-auth/internal/utils"
)

// backchannelLogoutEvent is the event name of an OIDC back-channel logout token.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// matchesConfiguredURL reports whether the request targets the configured
// URL. The reference accepts three forms for `loginUrl`/`logoutUrl` (and the
// post-login/logout redirects): a path (`/login`), a host and a path
// (`example.com/login`) or an absolute URL (`https://example.com/login`). Only
// http/https are meaningful; the scheme itself is not compared, so a deployment
// behind TLS termination matches too.
func matchesConfiguredURL(req *http.Request, configured string) bool {
	if configured == "" || req == nil {
		return false
	}

	raw := configured
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if !pathMatches(req.URL.Path, path) {
		return false
	}

	if parsed.Host != "" {
		requestHost := req.Host
		if forwarded := req.Header.Get("X-Forwarded-Host"); forwarded != "" {
			requestHost = forwarded
		}
		if requestHost == "" {
			requestHost = req.URL.Host
		}
		if !strings.EqualFold(parsed.Host, requestHost) {
			return false
		}
	}

	return true
}

// discoveryURL returns a copy of the issuer URL carrying the extra discovery
// query parameters (`discoveryParams`).
func discoveryURL(issuer *url.URL, params map[string]string) *url.URL {
	if issuer == nil || len(params) == 0 {
		return issuer
	}

	clone := *issuer
	query := clone.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	clone.RawQuery = query.Encode()
	return &clone
}

// pathMatches reports whether a request path targets the configured login or
// logout path. A prefix match alone is wrong: `/login` would also match
// `/login-x` and `/login-evil`. Accept the exact path or a sub-path of it.
func pathMatches(requestPath, configuredPath string) bool {
	if requestPath == configuredPath {
		return true
	}
	if configuredPath == "/" {
		return true
	}
	return strings.HasPrefix(requestPath, strings.TrimSuffix(configuredPath, "/")+"/")
}

// attachForwardHeaders implements `forwardHeaders` and `forwardIDTokenHeader`.
//
// A claim that is missing removes the header from the request, even when the
// client sent a value, like the reference middleware does.
func (toa *TraefikOidcAuth) attachForwardHeaders(req *http.Request, sessionState *session.SessionState, tokenClaims map[string]interface{}) {
	// The reference extracts the forwarded values from the access token claims;
	// the ID token is used as a fallback. An explicit `id_token.` /
	// `access_token.` prefix selects the token. The second token is only parsed
	// when a forwardHeader actually needs it (it is a separate validation).
	var values claims.Values
	if len(toa.Config.ForwardHeaders) > 0 {
		values = toa.authorizationValues(sessionState, tokenClaims)
	}

	for _, forward := range toa.Config.ForwardHeaders {
		value, ok := lookupForwardClaim(values, forward.Claim)
		if !ok {
			req.Header.Del(forward.Name)
			continue
		}

		switch v := value.(type) {
		case []interface{}:
			if len(v) == 0 {
				req.Header.Del(forward.Name)
				continue
			}
			req.Header.Set(forward.Name, claimString(v[0]))
			for _, item := range v[1:] {
				req.Header.Add(forward.Name, claimString(item))
			}
		case []string:
			if len(v) == 0 {
				req.Header.Del(forward.Name)
				continue
			}
			req.Header.Set(forward.Name, v[0])
			for _, item := range v[1:] {
				req.Header.Add(forward.Name, item)
			}
		default:
			req.Header.Set(forward.Name, claimString(value))
		}
	}

	if toa.Config.ForwardIDTokenHeader != "" {
		if sessionState.IdToken != "" {
			req.Header.Set(toa.Config.ForwardIDTokenHeader, sessionState.IdToken)
		} else {
			req.Header.Del(toa.Config.ForwardIDTokenHeader)
		}
	}

	if toa.Config.UsernameClaim != "" {
		if value, ok := lookupClaim(tokenClaims, toa.Config.UsernameClaim); ok {
			toa.logger.Log(logging.LevelDebug, "Authenticated user %q (claim %s)", claimString(value), toa.Config.UsernameClaim)
		}
	}

	// `identity` names the caller (used by Hub to partition its semantic
	// cache). A middleware plugin has no such cache, so the resolved identity
	// is exposed through the logs only.
	if toa.Config.IdentityClaim != "" {
		if value, ok := lookupClaim(tokenClaims, toa.Config.IdentityClaim); ok {
			toa.logger.Log(logging.LevelDebug, "Caller identity %q (claim %s)", claimString(value), toa.Config.IdentityClaim)
		}
	}

	// N1: opt-in injection of the upstream bearer token. It is only forwarded
	// for an authorized session, so an unauthenticated (or pre-upgrade) session
	// cannot leak a stale token upstream; say so in the log so the drop is
	// observable.
	if toa.Config.ForwardAccessToken && sessionState.AccessToken != "" && req.Header.Get("Authorization") == "" {
		if !sessionState.IsAuthorized {
			toa.logger.Log(logging.LevelDebug, "Not forwarding the access token: the session is not authorized")
		} else {
			req.Header.Set("Authorization", "Bearer "+sessionState.AccessToken)
		}
	}
}

// lookupForwardClaim resolves a `forwardHeaders` claim: an explicit prefix
// selects the token, otherwise the access token is tried first and the ID
// token second.
func lookupForwardClaim(values claims.Values, key string) (interface{}, bool) {
	if strings.HasPrefix(key, "id_token.") {
		return lookupClaim(values.IDToken, strings.TrimPrefix(key, "id_token."))
	}
	if strings.HasPrefix(key, "access_token.") {
		return lookupClaim(values.AccessToken, strings.TrimPrefix(key, "access_token."))
	}

	if value, ok := lookupClaim(values.AccessToken, key); ok {
		return value, true
	}
	return lookupClaim(values.IDToken, key)
}

// sessionStoreUnavailable reports whether an error comes from the session
// store (used to fail closed with a 503 instead of a forced re-login).
func sessionStoreUnavailable(err error) bool {
	return errors.Is(err, session.ErrSessionStoreUnavailable)
}

// emptySession is a session used for the requests that have none (public
// bypass routes, Forward behaviour), so that the header injection runs.
func emptySession() *session.SessionState { return &session.SessionState{} }

// csrfConfig is the CSRF configuration derived from the session cookie and the
// `csrf` section.
func (toa *TraefikOidcAuth) csrfConfig() csrf.Config {
	if toa.Config.CSRF == nil {
		return csrf.Config{}
	}

	return csrf.Config{
		HeaderName: toa.Config.CSRF.HeaderName,
		Path:       toa.Config.SessionCookie.Path,
		Domain:     toa.Config.SessionCookie.Domain,
		SameSite:   toa.Config.SessionCookie.SameSite,
		Secure:     toa.Config.CSRF.Secure || toa.Config.SessionCookie.Secure,
		MaxAge:     toa.Config.SessionExpiry,
	}
}

// csrfBinding is the value a CSRF token is bound to. For an internal session it
// is the session id; for the header/cookie authentication path (whose session
// id is a fixed literal) it is derived from the token, so a token issued for
// one client cannot be replayed by another.
func csrfBinding(sessionState *session.SessionState) string {
	if sessionState == nil {
		return ""
	}

	if sessionState.Id == "AuthorizationHeader" || sessionState.Id == "AuthorizationCookie" {
		sum := sha256.Sum256([]byte(sessionState.AccessToken))
		return hex.EncodeToString(sum[:])
	}

	return sessionState.Id
}

// clearCSRFCookie expires the CSRF cookie, so that it does not outlive the
// session it protected.
func (toa *TraefikOidcAuth) clearCSRFCookie(rw http.ResponseWriter, req *http.Request) {
	if toa.Config.CSRF == nil || !toa.Config.CSRF.Enabled {
		return
	}

	cfg := toa.csrfConfig()
	name := csrf.CookieName(cfg)

	paths := []string{cfg.Path}
	if cfg.Path != "/" {
		paths = append(paths, "/")
	}

	for _, path := range paths {
		if path == "" {
			path = "/"
		}
		http.SetCookie(rw, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     path,
			Domain:   cfg.Domain,
			Secure:   cfg.Secure,
			HttpOnly: cfg.HTTPOnly,
			SameSite: parseCookieSameSite(cfg.SameSite),
			MaxAge:   -1,
			Expires:  time.Now().Add(-24 * time.Hour),
		})
	}
}

// enforceCSRF applies the CSRF protection. It returns false when the request
// has been rejected (the response is already written).
func (toa *TraefikOidcAuth) enforceCSRF(rw http.ResponseWriter, req *http.Request, sessionState *session.SessionState) bool {
	if toa.CSRF == nil {
		return true
	}

	cfg := toa.csrfConfig()
	binding := csrfBinding(sessionState)

	if csrf.IsSafeMethod(req.Method) {
		toa.CSRF.EnsureCookie(cfg, rw, req, binding)
		return true
	}

	if err := toa.CSRF.Validate(cfg, req, binding); err != nil {
		toa.logger.Log(logging.LevelWarn, "CSRF validation failed: %s", err.Error())
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return false
	}

	return true
}

// isBackchannelLogoutRequest reports whether the request targets the
// back-channel logout endpoint.
func (toa *TraefikOidcAuth) isBackchannelLogoutRequest(req *http.Request) bool {
	if toa.Config.BackchannelLogout == nil || !toa.Config.BackchannelLogout.Enabled {
		return false
	}

	if req.Method != http.MethodPost {
		return false
	}

	u := *req.URL
	utils.FillHostSchemeFromRequest(req, &u)
	return u.Path == toa.Config.BackchannelLogout.Path
}

// handleBackchannelLogout processes an OIDC back-channel logout token: it
// validates the token and revokes the matching sessions.
func (toa *TraefikOidcAuth) handleBackchannelLogout(rw http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(rw, "Bad Request", http.StatusBadRequest)
		return
	}

	logoutToken := req.PostFormValue("logout_token")
	if logoutToken == "" {
		http.Error(rw, "logout_token is missing", http.StatusBadRequest)
		return
	}

	logoutClaims, err := toa.validateBackchannelLogoutToken(logoutToken)
	if err != nil {
		toa.logger.Log(logging.LevelWarn, "Invalid back-channel logout token: %s", err.Error())
		http.Error(rw, "Bad Request", http.StatusBadRequest)
		return
	}

	sid, _ := logoutClaims["sid"].(string)
	sub, _ := logoutClaims["sub"].(string)

	if toa.Config.BackchannelLogout.SessionsRequired && sid == "" {
		toa.logger.Log(logging.LevelWarn, "Back-channel logout token has no sid claim, but backchannelLogoutSessionsRequired is set")
		http.Error(rw, "Bad Request", http.StatusBadRequest)
		return
	}

	if toa.Revoker == nil {
		toa.logger.Log(logging.LevelWarn, "Back-channel logout received, but the sessions are kept in a cookie and cannot be revoked server-side. Configure a Redis session store to enable server-side logout.")
		rw.WriteHeader(http.StatusOK)
		return
	}

	// The sid identifies the session being logged out; the sub additionally
	// covers the other sessions of the same user (Keycloak semantics).
	revoked := 0
	if sid != "" {
		n, err := toa.Revoker.RevokeBySid(sid)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Failed to revoke the session %s: %s", sid, err.Error())
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		revoked += n
	}
	if sub != "" {
		n, err := toa.Revoker.RevokeBySub(sub)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Failed to revoke the sessions of %s: %s", sub, err.Error())
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		revoked += n
	}

	toa.logger.Log(logging.LevelInfo, "Back-channel logout: %d session(s) revoked", revoked)
	rw.WriteHeader(http.StatusOK)
}

// validateBackchannelLogoutToken verifies the logout token: signature, issuer,
// audience, age and the backchannel-logout event.
func (toa *TraefikOidcAuth) validateBackchannelLogoutToken(tokenString string) (jwt.MapClaims, error) {
	if toa.jwks() == nil {
		return nil, errors.New("OIDC discovery is not loaded yet")
	}
	if err := toa.jwks().EnsureLoaded(toa.logger, toa.httpClient, false); err != nil {
		return nil, err
	}

	options := []jwt.ParserOption{}
	if toa.Config.Provider.ValidateIssuerBool {
		options = append(options, jwt.WithIssuer(toa.issuer()))
	}
	if toa.Config.Provider.ValidateAudienceBool {
		options = append(options, jwt.WithAudience(toa.audience()))
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(options...)
	if _, err := parser.ParseWithClaims(tokenString, claims, toa.jwks().Keyfunc); err != nil {
		return nil, err
	}

	// The token must target the backchannel-logout event.
	events, ok := claims["events"].(map[string]interface{})
	if !ok || events[backchannelLogoutEvent] == nil {
		return nil, errors.New("the token does not carry the back-channel logout event")
	}

	if _, ok := claims["nonce"]; ok {
		return nil, errors.New("a back-channel logout token must not carry a nonce")
	}

	// OIDC Back-Channel Logout 1.0 requires jti and iat, and the token must
	// identify the session through a sid or a sub claim.
	if _, ok := claims["jti"]; !ok {
		return nil, errors.New("the logout token has no jti claim")
	}

	iat, ok := claims["iat"]
	if !ok {
		return nil, errors.New("the logout token has no iat claim")
	}
	issuedAt, err := claimTime(iat)
	if err != nil {
		return nil, err
	}
	if time.Since(issuedAt) > 5*time.Minute {
		return nil, errors.New("the logout token is too old")
	}

	sid, _ := claims["sid"].(string)
	sub, _ := claims["sub"].(string)
	if sid == "" && sub == "" {
		return nil, errors.New("the logout token has neither a sid nor a sub claim")
	}

	return claims, nil
}

// authorizationValues builds the two claim sets used by the `claims`
// expression. The claims of the token selected by tokenValidation are already
// known; the other token is parsed locally (best effort) so that a prefixed
// key (`access_token.` / `id_token.`) resolves.
func (toa *TraefikOidcAuth) authorizationValues(sessionState *session.SessionState, tokenClaims map[string]interface{}) claims.Values {
	values := claims.Values{}

	switch toa.Config.Provider.TokenValidation {
	case "AccessToken", "Introspection":
		values.AccessToken = normalizeClaims(tokenClaims)
	default:
		values.IDToken = normalizeClaims(tokenClaims)
	}

	if sessionState == nil {
		return values
	}

	if values.IDToken == nil && sessionState.IdToken != "" {
		if ok, parsed, err := toa.validateTokenClaims(sessionState.IdToken, toa.Config.Provider.ValidateAudienceBool); ok && err == nil {
			values.IDToken = normalizeClaims(parsed)
		}
	}
	if values.AccessToken == nil && sessionState.AccessToken != "" {
		// No audience check here: the ID token audience is meaningless for an
		// access token (Keycloak does not even set an `aud` claim on it).
		if ok, parsed, err := toa.validateTokenClaims(sessionState.AccessToken, false); ok && err == nil {
			values.AccessToken = normalizeClaims(parsed)
		}
	}

	return values
}

// normalizeClaims rebuilds the claim map through encoding/json.
//
// golang-jwt decodes the tokens into a named map type (jwt.MapClaims). Under
// yaegi 0.16.1 such a named map does not satisfy an `interface{}` holding a
// plain `map[string]interface{}` in a type assertion, so the nested claim
// lookup of the `claims` expression would fail. A JSON round-trip guarantees
// the stdlib types the evaluator expects at every level.
func normalizeClaims(claimMap map[string]interface{}) map[string]interface{} {
	if claimMap == nil {
		return nil
	}

	raw, err := json.Marshal(claimMap)
	if err != nil {
		return claimMap
	}

	normalized := map[string]interface{}{}
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return claimMap
	}

	return normalized
}

// claimAsString returns a string claim, or "" when it is missing or not a string.
func claimAsString(tokenClaims map[string]interface{}, key string) string {
	if tokenClaims == nil {
		return ""
	}
	if value, ok := tokenClaims[key].(string); ok {
		return value
	}
	return ""
}

// lookupClaim resolves a possibly nested claim (dot path) and reports whether
// it exists.
func lookupClaim(tokenClaims map[string]interface{}, path string) (interface{}, bool) {
	if path == "" || tokenClaims == nil {
		return nil, false
	}

	var current interface{} = tokenClaims
	for _, segment := range strings.Split(path, ".") {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = m[segment]
		if !ok {
			return nil, false
		}
	}

	return current, true
}

func claimString(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func claimTime(value interface{}) (time.Time, error) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0), nil
	case int64:
		return time.Unix(v, 0), nil
	case json.Number:
		seconds, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(seconds, 0), nil
	default:
		return time.Time{}, errors.New("invalid iat claim")
	}
}
