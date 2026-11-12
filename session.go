package traefik_keycloak_auth

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/session"
)

var errNoSessionCookie = errors.New("no session cookie is present")
var errNoSession = errors.New("no session was found for the session ticket")

func (toa *TraefikOidcAuth) getSessionForRequest(req *http.Request) (*session.SessionState, bool, map[string]interface{}, error) {
	// Use AuthorizationHeader, if present
	if toa.Config.AuthorizationHeader != nil && toa.Config.AuthorizationHeader.Name != "" {
		authHeader := req.Header.Get(toa.Config.AuthorizationHeader.Name)

		if authHeader != "" {
			if toa.Config.AuthorizationHeader.Name == "Authorization" {
				authHeader = strings.TrimPrefix(authHeader, "Bearer ")
			}

			toa.logger.Log(logging.LevelDebug, "Custom AuthorizationHeader is present on the request and will be used.")

			session := &session.SessionState{
				Id:          "AuthorizationHeader",
				AccessToken: authHeader,
			}

			ok, claims, err := toa.validateToken(session)

			if ok {
				return session, false, claims, err
			} else {
				return nil, false, nil, fmt.Errorf("failed to validate token from AuthorizationHeader: %s", err.Error())
			}
		}
	}

	// Use AuthorizationCookie, if present
	if toa.Config.AuthorizationCookie != nil && toa.Config.AuthorizationCookie.Name != "" {
		authCookie, err := req.Cookie(toa.Config.AuthorizationCookie.Name)

		if authCookie != nil && err == nil && authCookie.Value != "" {
			toa.logger.Log(logging.LevelDebug, "Custom AuthorizationCookie is present on the request and will be used.")

			session := &session.SessionState{
				Id:          "AuthorizationCookie",
				AccessToken: authCookie.Value,
			}

			ok, claims, err := toa.validateToken(session)

			if ok {
				return session, false, claims, err
			} else {
				return nil, false, nil, fmt.Errorf("failed to validate token from AuthorizationCookie: %s", err.Error())
			}
		}
	}

	// Use SessionCookie, if present
	sessionTicket, err := readChunkedCookie(req, getSessionCookieName(toa.Config))

	if err != nil {
		if err == http.ErrNoCookie {
			return nil, false, nil, errNoSessionCookie
		}

		return nil, false, nil, fmt.Errorf("unable to read session cookie: %s", err.Error())
	}
	if sessionTicket == "" {
		return nil, false, nil, errNoSessionCookie
	}

	session, claims, updatedSession, err := validateSessionTicket(toa, sessionTicket)

	if err != nil {
		if err == errNoSession {
			return nil, false, claims, errNoSession
		}

		return nil, false, claims, fmt.Errorf("failed to validate session ticket: %w", err)
	}

	if toa.logger.MinLevel == logging.LevelDebug {
		tokenExpiresText := ""
		if session.TokenExpiresIn > 0 {
			tokenExpiresText = fmt.Sprintf("The IDP token expires in %ds.", int(math.Round(time.Until(session.RefreshedAt.Add(time.Duration(session.TokenExpiresIn)*time.Second)).Seconds())))
		}

		toa.logger.Log(logging.LevelDebug, "A session is present for the request. %s", tokenExpiresText)
	}

	return session, updatedSession != nil, claims, nil
}

func validateSessionTicket(toa *TraefikOidcAuth, sessionTicket string) (*session.SessionState, map[string]interface{}, *session.SessionState, error) {
	session, err := toa.SessionStorage.TryGetSession(toa.logger, toa.Config, sessionTicket)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Reading session failed: %v", err.Error())
		return nil, nil, nil, err
	}
	if session == nil {
		toa.logger.Log(logging.LevelDebug, "No session found")
		return nil, nil, nil, errNoSession
	}

	// A session stored before AuthenticatedAt existed has a zero value; anchor
	// it to a fixed instant (its refresh time) and persist it, so that
	// session.maxAge is enforced from then on instead of a moving one.
	backfilled := false
	if session.AuthenticatedAt.IsZero() && toa.Config.SessionMaxAge > 0 {
		session.AuthenticatedAt = session.RefreshedAt
		backfilled = true
	}

	// session.maxAge bounds the end-user authentication itself: past it, the
	// tokens are irrelevant and the user must authenticate again.
	if expiredByMaxAge(toa, session) {
		toa.logger.Log(logging.LevelInfo, "The session exceeded session.maxAge, re-authentication is required.")
		return nil, nil, nil, errNoSession
	}

	success, claims, err := toa.validateToken(session)

	// Check if the session or IDP token expires soon
	idpTokenExpiresSoon := false
	if success {
		idpTokenExpiresSoon = checkIdpTokenExpiresSoon(toa, session)
	}

	if !success || err != nil || idpTokenExpiresSoon {
		if session.RefreshToken != "" && toa.Config.SessionRefresh {
			toa.logger.Log(logging.LevelInfo, "Trying to renew tokens...")

			newTokens, err := toa.renewToken(session.RefreshToken)

			if err != nil {
				return nil, nil, nil, err
			}

			session.AccessToken = newTokens.AccessToken

			if newTokens.RefreshToken != "" {
				session.RefreshToken = newTokens.RefreshToken
			} else {
				toa.logger.Log(logging.LevelDebug, "The auth provider didn't return a new RefreshToken. Still keeping the old one.")
			}

			// We had some problems with some providers which didn't return a new IdToken when renewing the tokens.
			// Thats why i'am logging this case specifically here.
			if newTokens.IdToken != "" {
				session.IdToken = newTokens.IdToken
			} else {
				if toa.Config.Provider.TokenValidation == "IdToken" {
					toa.logger.Log(logging.LevelWarn, "The auth provider didn't return a new IdToken. Still keeping the old one.")
				} else {
					toa.logger.Log(logging.LevelDebug, "The auth provider didn't return a new IdToken. Still keeping the old one.")
				}
			}

			success, claims, err = toa.validateToken(session)

			if !success || err != nil {
				toa.logger.Log(logging.LevelError, "Failed to validate renewed session: %v", err)
				return nil, nil, session, err
			}

			// Update expirations
			session.RefreshedAt = time.Now()
			session.TokenExpiresIn = newTokens.ExpiresIn
			if session.TokenExpiresIn <= 0 {
				session.TokenExpiresIn = expiresInFromClaims(claims)
			}

			toa.logger.Log(logging.LevelInfo, "Successfully renewed session")

			return session, claims, session, err
		} else {
			if err == nil {
				if !toa.Config.SessionRefresh {
					err = errors.New("token refresh is disabled (session.refresh=false)")
				} else {
					err = errors.New("no refresh_token available")
				}
			}
			return nil, nil, nil, err
		}
	}

	if backfilled {
		// Ask the caller to persist the anchored timestamp.
		return session, claims, session, nil
	}

	return session, claims, nil, nil
}

func checkIdpTokenExpiresSoon(toa *TraefikOidcAuth, session *session.SessionState) bool {
	// With the refresh disabled, an expiring token must not trigger a
	// re-authentication earlier than its actual expiration.
	if !toa.Config.SessionRefresh {
		return false
	}

	if session.TokenExpiresIn > 0 {
		pastDuration := time.Since(session.RefreshedAt)

		halfMaxAge := float64(session.TokenExpiresIn) * toa.Config.Provider.TokenRenewalThreshold

		if pastDuration.Seconds() > halfMaxAge {
			toa.logger.Log(logging.LevelDebug, "The IDP token reached %d%% of it's expiration. Renewing now...", int32(toa.Config.Provider.TokenRenewalThreshold*100))
			return true
		}
	}

	return false
}

func (toa *TraefikOidcAuth) validateToken(session *session.SessionState) (bool, map[string]interface{}, error) {
	var token string

	// Little bit hacky. In case the request contains a custom AuthorizationHeader or Cookie, only AccessToken is used.
	// See getSessionForRequest-function.
	if session.Id == "AuthorizationHeader" || session.Id == "AuthorizationCookie" {
		token = session.AccessToken
	} else {
		switch toa.Config.Provider.TokenValidation {
		case "AccessToken", "Introspection":
			token = session.AccessToken
		case "IdToken":
			token = session.IdToken
		default:
			return false, nil, errors.New(fmt.Sprintf("Invalid value '%s' for TokenValidation", toa.Config.Provider.TokenValidation))
		}
	}

	if token == "" {
		return false, nil, fmt.Errorf("the session contains no %s, which is required by TokenValidation '%s'", validatedTokenName(toa.Config.Provider.TokenValidation), toa.Config.Provider.TokenValidation)
	}

	if toa.Config.Provider.TokenValidation == "Introspection" {
		return toa.introspectToken(token)
	}

	ok, claims, err := toa.validateTokenLocally(token)

	if !ok {
		return ok, claims, err
	}

	if toa.Config.Provider.UseClaimsFromUserInfoBool {
		subClaim, ok := claims["sub"].(string)
		if !ok {
			return false, nil, fmt.Errorf("failed to fetch UserInfo: 'sub' claim is not a string or missing")
		}

		userInfoClaims, err := toa.getUserInfo(session.AccessToken, subClaim)
		if err != nil {
			return false, nil, fmt.Errorf("failed to fetch UserInfo: %s", err.Error())
		}

		claims = mergeClaims(claims, userInfoClaims)
	}

	return ok, claims, err
}

func validatedTokenName(tokenValidation string) string {
	if tokenValidation == "IdToken" {
		return "id_token"
	}

	return "access_token"
}

// renewSession persists a sliding/refresh renewal. Unlike the login/callback
// path it must not fail the request: the session is valid and was just read
// successfully, so a store hiccup only means the renewal is lost. Failing here
// would turn every request into a 503 for the whole failover window.
func (toa *TraefikOidcAuth) renewSession(session *session.SessionState, rw http.ResponseWriter) {
	sessionTicket, err := toa.SessionStorage.StoreSession(toa.logger, toa.Config, session.Id, session)
	if err != nil {
		toa.logger.Log(logging.LevelWarn, "Could not renew the session, serving the request with the existing one: %s", err.Error())
		return
	}

	toa.logger.Log(logging.LevelDebug, "Session renewed. Id %s", session.Id)

	if err := setChunkedCookies(toa.Config, rw, getSessionCookieName(toa.Config), sessionTicket); err != nil {
		toa.logger.Log(logging.LevelWarn, "Could not refresh the session cookie: %s", err.Error())
	}
}

// storeSessionAndAttachCookie persists the session and sets the session cookie.
// It returns false when it already wrote an error response, so the caller must
// stop instead of writing a second response or forwarding the request.
func (toa *TraefikOidcAuth) storeSessionAndAttachCookie(session *session.SessionState, rw http.ResponseWriter) bool {
	sessionTicket, err := toa.SessionStorage.StoreSession(toa.logger, toa.Config, session.Id, session)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to store session: %s", err.Error())
		// A store outage is retryable, not an internal error: fail closed with
		// the same status the read path uses (R12).
		if sessionStoreUnavailable(err) {
			http.Error(rw, "Service Unavailable", http.StatusServiceUnavailable)
			return false
		}
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return false
	}

	toa.logger.Log(logging.LevelDebug, "Session stored. Id %s", session.Id)

	err = setChunkedCookies(toa.Config, rw, getSessionCookieName(toa.Config), sessionTicket)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to store the session in a cookie: %s", err.Error())
		http.Error(rw, "Failed to store the session", http.StatusInternalServerError)
		return false
	}

	return true
}

func createSessionCookie(config *config.Config) *http.Cookie {
	return &http.Cookie{
		Name:     getSessionCookieName(config),
		Value:    "",
		Secure:   config.SessionCookie.Secure,
		HttpOnly: config.SessionCookie.HttpOnly,
		Path:     config.SessionCookie.Path,
		Domain:   config.SessionCookie.Domain,
		SameSite: parseCookieSameSite(config.SessionCookie.SameSite),
		MaxAge:   config.SessionCookie.MaxAge,
	}
}

// expiredByMaxAge reports whether the session exceeded the absolute
// `session.maxAge` (a zero or negative maxAge disables the check).
func expiredByMaxAge(toa *TraefikOidcAuth, state *session.SessionState) bool {
	if toa.Config.SessionMaxAge <= 0 {
		return false
	}

	authenticatedAt := state.AuthenticatedAt
	if authenticatedAt.IsZero() {
		authenticatedAt = state.RefreshedAt
	}
	if authenticatedAt.IsZero() {
		return false
	}

	return time.Since(authenticatedAt) > time.Duration(toa.Config.SessionMaxAge)*time.Second
}
