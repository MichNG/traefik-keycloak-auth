package traefik_keycloak_auth

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/oidc"
	"github.com/MichNG/traefik-keycloak-auth/internal/utils"
)

const (
	cookieChunkSize = 3072
	maxCookieChunks = 16

	// How long the browser binding cookie lives, in seconds. It's refreshed whenever a login starts.
	// It matches the `stateCookie.maxAge` default so both paths agree.
	browserBindingMaxAge = 600
	// The number of random bytes in a browser binding. Hex encoded, so the value is twice as long.
	browserBindingBytes = 32
)

func setChunkedCookies(config *config.Config, rw http.ResponseWriter, cookieName string, cookieValue string) error {
	cookieChunks := utils.ChunkString(cookieValue, cookieChunkSize)

	if len(cookieChunks) > maxCookieChunks {
		return fmt.Errorf("the session needs %d cookie chunks but only %d are supported", len(cookieChunks), maxCookieChunks)
	}

	baseCookie := createSessionCookie(config)
	baseCookie.Name = cookieName

	// Set the cookie
	if len(cookieChunks) == 1 {
		c := baseCookie
		c.Value = cookieValue
		http.SetCookie(rw, c)
	} else {
		c := baseCookie
		c.Name = cookieName + ".Chunks"
		c.Value = fmt.Sprintf("%d", len(cookieChunks))
		http.SetCookie(rw, c)

		for index, chunk := range cookieChunks {
			c.Name = fmt.Sprintf("%s.%d", cookieName, index+1)
			c.Value = chunk
			http.SetCookie(rw, c)
		}
	}

	return nil
}
func readChunkedCookie(req *http.Request, cookieName string) (string, error) {
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		return "", err
	}

	if chunkCount == 0 {
		cookie, err := req.Cookie(cookieName)
		if err != nil {
			return "", err
		}

		return cookie.Value, nil
	}

	value := ""

	for i := 0; i < chunkCount; i++ {
		cookie, err := req.Cookie(fmt.Sprintf("%s.%d", cookieName, i+1))
		if err != nil {
			return "", fmt.Errorf("chunk %d of %d is missing, the session cookie was truncated", i+1, chunkCount)
		}

		value += cookie.Value
	}

	return value, nil
}
func getChunkedCookieCount(req *http.Request, cookieName string) (int, error) {
	chunksCookie, err := req.Cookie(fmt.Sprintf("%s.Chunks", cookieName))
	if err != nil {
		return 0, nil
	}

	chunkCount, err := strconv.Atoi(chunksCookie.Value)
	if err != nil {
		return 0, err
	}

	if chunkCount < 0 || chunkCount > maxCookieChunks {
		return 0, fmt.Errorf("cookie %s.Chunks contains an out of range chunk count of %d", cookieName, chunkCount)
	}

	return chunkCount, nil
}
func clearChunkedCookie(config *config.Config, rw http.ResponseWriter, req *http.Request, cookieName string) {
	baseCookie := createSessionCookie(config)
	baseCookie.Value = ""
	makeCookieExpireImmediately(baseCookie)

	for _, name := range presentChunkedCookieNames(req, cookieName) {
		c := *baseCookie
		c.Name = name
		http.SetCookie(rw, &c)
	}
}

func presentChunkedCookieNames(req *http.Request, cookieName string) []string {
	names := []string{cookieName}
	prefix := cookieName + "."

	for _, c := range req.Cookies() {
		if len(names) >= maxCookieChunks+2 {
			break
		}

		if strings.HasPrefix(c.Name, prefix) {
			names = append(names, c.Name)
		}
	}

	return names
}

func parseCookieSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteDefaultMode
	}
}

func makeCookieExpireImmediately(cookie *http.Cookie) *http.Cookie {
	cookie.Expires = time.Now().Add(-24 * time.Hour)
	cookie.MaxAge = -1
	return cookie
}

func getCodeVerifierCookieName(config *config.Config) string {
	return makeCookieName(config, "CodeVerifier")
}

func getSessionCookieName(config *config.Config) string {
	if config.SessionCookieName != "" {
		return config.SessionCookieName
	}
	return makeCookieName(config, "Session")
}

func getBrowserBindingCookieName(config *config.Config) string {
	if config.StateCookieName != "" {
		return config.StateCookieName
	}
	return makeCookieName(config, "BrowserBinding")
}

// ensureBrowserBinding returns the value binding an OIDC state to this browser and attaches the cookie
// holding it to the response.
//
// An existing value is reused so parallel flows of the same browser don't overwrite each other's
// binding. The cookie is deliberately not cleared after a login, because another flow of this browser
// may still be in progress. It just expires.
func ensureBrowserBinding(cfg *config.Config, rw http.ResponseWriter, req *http.Request) (string, error) {
	value := ""

	if cookie, err := req.Cookie(getBrowserBindingCookieName(cfg)); err == nil && isWellFormedBrowserBinding(cookie.Value) {
		value = cookie.Value
	} else {
		generated, err := randomBytesInHex(browserBindingBytes)
		if err != nil {
			return "", err
		}
		value = generated
	}

	// The state cookie settings come from `stateCookie.*`. SameSite=Strict
	// would never work here, as the callback is a cross-site navigation coming
	// from the identity provider, so `lax` is the default.
	stateCookie := cfg.StateCookie
	if stateCookie == nil {
		stateCookie = defaultStateCookie()
	}

	path := stateCookie.Path
	if path == "" {
		path = "/"
	}
	maxAge := stateCookie.MaxAge
	if maxAge == 0 {
		maxAge = browserBindingMaxAge
	}
	sameSite := parseCookieSameSite(stateCookie.SameSite)
	if stateCookie.SameSite == "" || stateCookie.SameSite == "default" {
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     getBrowserBindingCookieName(cfg),
		Value:    value,
		Path:     path,
		Domain:   stateCookie.Domain,
		Secure:   stateCookie.Secure,
		HttpOnly: stateCookie.HttpOnly,
		SameSite: sameSite,
		MaxAge:   maxAge,
	})

	return value, nil
}

// isWellFormedBrowserBinding only accepts values ensureBrowserBinding could have generated.
func isWellFormedBrowserBinding(value string) bool {
	if len(value) != browserBindingBytes*2 {
		return false
	}

	_, err := hex.DecodeString(value)
	return err == nil
}

// isBrowserBindingValid reports whether the given state was issued to the browser sending this request.
// A state without a binding never matches: states don't expire, so accepting one
// would allow replaying a state issued by an older version.
func isBrowserBindingValid(config *config.Config, req *http.Request, state *oidc.OidcState) bool {
	if state.BrowserBinding == "" {
		return false
	}

	cookie, err := req.Cookie(getBrowserBindingCookieName(config))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state.BrowserBinding)) == 1
}

func makeCookieName(config *config.Config, name string) string {
	return fmt.Sprintf("%s.%s", config.CookieNamePrefix, name)
}

// clearLegacyCodeVerifierCookies expires PKCE cookies left by older builds.
// Temporary upgrade hygiene — safe to delete once those builds are gone.
//
// Browsers treat Domain=host and host-only (no Domain) as different cookies.
// We expire both. See makeCookieExpireImmediately for MaxAge=-1 behavior.
func clearLegacyCodeVerifierCookies(config *config.Config, rw http.ResponseWriter, req *http.Request, callbackURL *url.URL) {
	if callbackURL == nil {
		return
	}

	prefix := getCodeVerifierCookieName(config)
	path := callbackURL.Path
	// Hostname() strips any port. Domain with a port is invalid for Set-Cookie;
	// older code used url.Host and often ended up with host-only cookies instead.
	hostname := callbackURL.Hostname()

	names := map[string]struct{}{prefix: {}}
	for _, c := range req.Cookies() {
		if c.Name == prefix || strings.HasPrefix(c.Name, prefix+".") {
			names[c.Name] = struct{}{}
		}
	}

	for name := range names {
		domains := []string{""} // host-only
		if hostname != "" {
			domains = append(domains, hostname)
		}
		for _, domain := range domains {
			http.SetCookie(rw, makeCookieExpireImmediately(&http.Cookie{
				Name:     name,
				Value:    "",
				Secure:   true,
				HttpOnly: true,
				Path:     path,
				Domain:   domain,
				SameSite: http.SameSiteDefaultMode,
			}))
		}
	}
}
