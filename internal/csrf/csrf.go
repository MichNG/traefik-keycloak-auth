// Package csrf implements the CSRF protection of the middleware: the Signed
// Double Submit Cookie pattern recommended by OWASP, as used by Traefik Hub.
//
// The middleware issues a signed token in a cookie and expects the client to
// echo the very same value in a header on unsafe requests. Because the token is
// HMAC-signed, an attacker who cannot read the cookie cannot forge one, and
// because it is bound to the session id, a token stolen from another session
// is rejected. The scheme requires no server-side state and no change to the
// upstream application.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultCookieName is the cookie name used by the reference middleware.
	DefaultCookieName = "hub-csrf-token"
	// DefaultHeaderName is the header name used by the reference middleware.
	DefaultHeaderName = "Hub-Csrf-Token"

	tokenVersion = "v1"
	nonceBytes   = 32
)

// ErrInvalidToken is returned when the CSRF token is missing, malformed or not
// signed by this middleware.
var ErrInvalidToken = errors.New("invalid CSRF token")

// Protector generates and verifies CSRF tokens.
type Protector struct {
	secret []byte
	ttl    time.Duration
}

// New builds a Protector. The secret must be the middleware secret.
func New(secret string, ttl time.Duration) *Protector {
	return &Protector{secret: []byte(secret), ttl: ttl}
}

// Generate returns a fresh token bound to the given session id (which may be
// empty for requests that have no session yet). The token embeds its issue
// time, so that a leaked token expires with the configured TTL even when it is
// presented outside its cookie.
func (p *Protector) Generate(binding string) (string, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("csrf: generating a nonce: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(nonce)
	issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
	sig := p.sign(encoded, issuedAt, binding)

	return strings.Join([]string{tokenVersion, encoded, issuedAt, sig}, "."), nil
}

// Verify reports whether the token is signed by this middleware, bound to the
// given session id, and still within its TTL.
func (p *Protector) Verify(token, binding string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != tokenVersion {
		return false
	}

	if p.ttl > 0 {
		issuedAt, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return false
		}
		if time.Since(time.Unix(issuedAt, 0)) > p.ttl {
			return false
		}
	}

	expected := p.sign(parts[1], parts[2], binding)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(parts[3])) == 1
}

// Equal reports whether two token strings are identical in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (p *Protector) sign(nonce, issuedAt, binding string) string {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(tokenVersion))
	mac.Write([]byte("|"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("|"))
	mac.Write([]byte(issuedAt))
	mac.Write([]byte("|"))
	mac.Write([]byte(binding))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Config carries the cookie settings of the CSRF cookie.
type Config struct {
	CookieName string
	HeaderName string
	Path       string
	Domain     string
	SameSite   string
	HTTPOnly   bool
	Secure     bool
	MaxAge     int
}

// EnsureCookie reads the CSRF cookie of the request and, when it is missing or
// invalid, issues a fresh one bound to the given session id.
//
// It is meant to be called on the requests that may be followed by a state
// changing one (safe methods), so that the browser always holds a valid token.
func (p *Protector) EnsureCookie(cfg Config, rw http.ResponseWriter, req *http.Request, binding string) {
	cookie, err := req.Cookie(cookieName(cfg))
	if err == nil && cookie.Value != "" && p.Verify(cookie.Value, binding) {
		return
	}

	token, err := p.Generate(binding)
	if err != nil {
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     cookieName(cfg),
		Value:    token,
		Path:     pathOrRoot(cfg.Path),
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: cfg.HTTPOnly,
		SameSite: parseSameSite(cfg.SameSite),
		MaxAge:   cfg.MaxAge,
	})
}

// Validate checks the double submit: the header must be present, equal to the
// cookie and correctly signed for the session.
func (p *Protector) Validate(cfg Config, req *http.Request, binding string) error {
	cookie, err := req.Cookie(cookieName(cfg))
	if err != nil || cookie.Value == "" {
		return fmt.Errorf("%w: the CSRF cookie is missing", ErrInvalidToken)
	}

	header := req.Header.Get(headerName(cfg))
	if header == "" {
		return fmt.Errorf("%w: the %s header is missing", ErrInvalidToken, headerName(cfg))
	}

	if !Equal(cookie.Value, header) {
		return fmt.Errorf("%w: the header does not match the cookie", ErrInvalidToken)
	}

	if !p.Verify(header, binding) {
		return fmt.Errorf("%w: the token is not valid for this session", ErrInvalidToken)
	}

	return nil
}

// IsSafeMethod reports whether a request method is safe (RFC 9110): the CSRF
// check must not be applied to it.
func IsSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// CookieName returns the CSRF cookie name of the configuration.
func CookieName(cfg Config) string { return cookieName(cfg) }

func cookieName(cfg Config) string {
	if cfg.CookieName != "" {
		return cfg.CookieName
	}
	return DefaultCookieName
}

func headerName(cfg Config) string {
	if cfg.HeaderName != "" {
		return cfg.HeaderName
	}
	return DefaultHeaderName
}

func pathOrRoot(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func parseSameSite(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteLaxMode
	}
}
