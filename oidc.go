package traefik_keycloak_auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/oidc"
	"github.com/golang-jwt/jwt/v5"
)

func GetOidcDiscovery(logger *logging.Logger, httpClient *http.Client, providerUrl *url.URL) (*oidc.OidcDiscovery, error) {
	wellKnownUrl := *providerUrl

	wellKnownUrl.Path = path.Join(wellKnownUrl.Path, ".well-known/openid-configuration")

	// // create a http client with configurable options
	// // needed to skip certificate verification
	// tr := &http.Transport{
	// 	MaxIdleConns:    10,
	// 	IdleConnTimeout: 30 * time.Second,
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	// client := &http.Client{Transport: tr}

	// Make HTTP GET request to the OpenID provider's discovery endpoint
	resp, err := doWithRetries(httpClient, defaultMaxRetries+1, logger, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, wellKnownUrl.String(), nil)
	})

	if err != nil {
		logger.Log(logging.LevelError, "http-get discovery endpoints - Err: %s", err.Error())
		return nil, errors.New("HTTP GET error")
	}

	defer resp.Body.Close()

	// Check if the response status code is successful
	if resp.StatusCode >= 300 {
		logger.Log(logging.LevelError, "http-get OIDC discovery endpoints - http status code: %s", resp.Status)
		return nil, errors.New("HTTP error - Status code: " + resp.Status)
	}

	// Decode the JSON response
	document := oidc.OidcDiscovery{}
	err = json.NewDecoder(resp.Body).Decode(&document)

	if err != nil {
		logger.Log(logging.LevelError, "Failed to decode OIDC discovery document. Status code: %s", err.Error())
		return &document, errors.New("Failed to decode OIDC discovery document. Status code: " + err.Error())
	}

	return &document, nil
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

func exchangeAuthCode(oidcAuth *TraefikOidcAuth, req *http.Request, authCode string, codeVerifier string) (*oidc.OidcTokenResponse, error) {
	redirectUrl := oidcAuth.GetAbsoluteCallbackURL(req).String()

	urlValues := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {oidcAuth.Config.Provider.ClientId},
		"code":         {authCode},
		"redirect_uri": {redirectUrl},
		"resource":     oidcAuth.Config.RequestedResources,
	}

	if oidcAuth.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", oidcAuth.Config.Provider.ClientSecret)
	}

	if oidcAuth.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := oidcAuth.getClientAssertionJwtToken()
		if err != nil {
			return nil, err
		}

		urlValues.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		urlValues.Add("client_assertion", clientAssertionToken)
	}

	if oidcAuth.Config.Provider.UsePkceBool {
		if codeVerifier == "" {
			return nil, errors.New("missing PKCE code verifier in state")
		}

		urlValues.Add("code_verifier", codeVerifier)
	}

	resp, err := postFormWithRetries(oidcAuth.httpClient, maxRetries(oidcAuth.Config)+1, oidcAuth.logger, oidcAuth.DiscoveryDocument.TokenEndpoint, urlValues)

	if err != nil {
		oidcAuth.logger.Log(logging.LevelError, "exchangeAuthCode: couldn't POST to Provider: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		oidcAuth.logger.Log(logging.LevelError, "exchangeAuthCode: the provider answered HTTP %d", resp.StatusCode)
		oidcAuth.logger.Log(logging.LevelDebug, "exchangeAuthCode: response body: %s", truncateForLog(string(body)))
		return nil, errors.New("invalid status code")
	}

	tokenResponse := &oidc.OidcTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		oidcAuth.logger.Log(logging.LevelError, "exchangeAuthCode: couldn't decode OidcTokenResponse: %s", err.Error())
		return nil, err
	}

	return tokenResponse, nil
}

func (toa *TraefikOidcAuth) validateTokenLocally(tokenString string) (bool, map[string]interface{}, error) {
	return toa.validateTokenClaims(tokenString, toa.Config.Provider.ValidateAudienceBool)
}

// validateTokenClaims verifies a JWT signature (and, optionally, its
// audience). The audience check is disabled when reading the second token of
// the `claims` expression: a Keycloak access token typically has no `aud`
// claim, and the ID token audience must not be imposed on it.
func (toa *TraefikOidcAuth) validateTokenClaims(tokenString string, validateAudience bool) (bool, map[string]interface{}, error) {
	if toa.jwks() == nil {
		return false, nil, errors.New("OIDC discovery is not loaded yet")
	}

	claims := jwt.MapClaims{}

	err := toa.jwks().EnsureLoaded(toa.logger, toa.httpClient, false)
	if err != nil {
		return false, nil, err
	}

	options := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		// Explicit allow-list: only the asymmetric signatures used by OIDC
		// providers, so `none` or an HMAC algorithm can never be accepted.
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	}

	if toa.Config.Provider.ValidateIssuerBool {
		options = append(options, jwt.WithIssuer(toa.issuer()))
	}
	if toa.Config.Provider.ValidateAudienceBool && validateAudience {
		options = append(options, jwt.WithAudience(toa.audience()))
	}

	parser := jwt.NewParser(options...)

	_, err = parser.ParseWithClaims(tokenString, claims, toa.jwks().Keyfunc)

	if err != nil {
		// If the token is expired, reloading JWKS won't help — skip the retry.
		if isTokenExpiredError(err) {
			toa.logger.Log(logging.LevelInfo, "The token is expired.")
			return false, nil, err
		}

		// For other errors (e.g. unknown kid after key rotation), force-reload JWKS and retry.
		err := toa.jwks().EnsureLoaded(toa.logger, toa.httpClient, true)
		if err != nil {
			return false, nil, err
		}

		_, err = parser.ParseWithClaims(tokenString, claims, toa.jwks().Keyfunc)

		if err != nil {
			if isTokenExpiredError(err) {
				toa.logger.Log(logging.LevelInfo, "The token is expired.")
			} else {
				toa.logger.Log(logging.LevelError, "Failed to parse token: %v", err)
			}

			return false, nil, err
		}
	}

	return true, claims, nil
}

// isTokenExpiredError checks whether the error indicates the JWT token is expired.
//
// Traefik compiles plugins via Yaegi (Go interpreter), which may not fully
// support the multi-error unwrapping needed by errors.Is on the joined error
// of golang-jwt/v5, so errors.Is is tried first and the message is used as a
// fallback. Both checks are kept in one place: a change of wording in a future
// golang-jwt release then only costs a redundant JWKS reload, never a wrong
// validation.
func isTokenExpiredError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, jwt.ErrTokenExpired) {
		return true
	}
	return strings.Contains(err.Error(), jwt.ErrTokenExpired.Error())
}

// expiresInFromClaims derives the token lifetime when the provider did not
// return expires_in, so that a token with a known exp is still refreshed
// proactively instead of failing first.
func expiresInFromClaims(claims map[string]interface{}) int {
	if claims == nil {
		return 0
	}

	switch exp := claims["exp"].(type) {
	case float64:
		return int(time.Until(time.Unix(int64(exp), 0)).Seconds())
	case int64:
		return int(time.Until(time.Unix(exp, 0)).Seconds())
	case json.Number:
		seconds, err := exp.Int64()
		if err != nil {
			return 0
		}
		return int(time.Until(time.Unix(seconds, 0)).Seconds())
	default:
		return 0
	}
}

func (toa *TraefikOidcAuth) introspectToken(token string) (bool, map[string]interface{}, error) {
	data := url.Values{
		"token": {token},
	}

	if toa.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := toa.getClientAssertionJwtToken()
		if err != nil {
			return false, nil, err
		}

		data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Add("client_assertion", clientAssertionToken)
	}

	//log(toa.Config.LogLevel, LogLevelDebug, "Token: %s", token)

	endpoint := toa.DiscoveryDocument.IntrospectionEndpoint

	//if endpoint == "" {
	//	endpoint = toa.DiscoveryDocument.UserinfoEndpoint
	//}

	resp, err := doWithRetries(toa.httpClient, maxRetries(toa.Config)+1, toa.logger, func() (*http.Request, error) {
		introspectionRequest, err := http.NewRequest(
			http.MethodPost,
			endpoint,
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			return nil, err
		}
		introspectionRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		introspectionRequest.SetBasicAuth(toa.Config.Provider.ClientId, toa.Config.Provider.ClientSecret)
		return introspectionRequest, nil
	})
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error on introspection request: %s", err.Error())
		return false, nil, err
	}

	defer resp.Body.Close()

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)

	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to decode introspection response: %s", err.Error())
		return false, nil, err
	}

	// TODO: Remove
	//toa.logAvailableClaims(introspectResponse)

	active, ok := introspectResponse["active"].(bool)
	if !ok {
		return false, nil, errors.New("received invalid introspection response")
	}

	return active, introspectResponse, nil
}

func (toa *TraefikOidcAuth) renewToken(refreshToken string) (*oidc.OidcTokenResponse, error) {
	urlValues := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {toa.Config.Provider.ClientId},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"refresh_token": {refreshToken},
		// RFC 8707 resource indicator (singular), like the code exchange.
		"resource": toa.Config.RequestedResources,
	}

	if toa.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", toa.Config.Provider.ClientSecret)
	}

	// private_key_jwt: send the client assertion when a key is configured,
	// exactly like the authorization code exchange does.
	if toa.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := toa.getClientAssertionJwtToken()
		if err != nil {
			return nil, err
		}
		urlValues.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		urlValues.Add("client_assertion", clientAssertionToken)
	}

	resp, err := postFormWithRetries(toa.httpClient, maxRetries(toa.Config)+1, toa.logger, toa.DiscoveryDocument.TokenEndpoint, urlValues)

	if err != nil {
		toa.logger.Log(logging.LevelError, "renewToken: couldn't POST to Provider: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		toa.logger.Log(logging.LevelError, "renewToken: the provider answered HTTP %d", resp.StatusCode)
		toa.logger.Log(logging.LevelDebug, "renewToken: response body: %s", truncateForLog(string(body)))
		return nil, errors.New("invalid status code")
	}

	tokenResponse := &oidc.OidcTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		toa.logger.Log(logging.LevelError, "renewToken: couldn't decode OidcTokenResponse: %s", err.Error())
		return nil, err
	}

	return tokenResponse, nil
}

func (toa *TraefikOidcAuth) getClientAssertionJwtToken() (string, error) {
	claims := jwt.MapClaims{
		"iss": toa.Config.Provider.ClientId,
		"sub": toa.Config.Provider.ClientId,
		"aud": toa.Config.Provider.Url,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}

	assertionToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	assertionToken.Header["kid"] = toa.Config.Provider.ClientJwtPrivateKeyId

	clientAssertionJwt, err := assertionToken.SignedString(toa.ClientJwtPrivateKey)
	if err != nil {
		return "", err
	}

	return clientAssertionJwt, nil
}

func (toa *TraefikOidcAuth) getUserInfo(accessToken string, idTokenSubject string) (map[string]interface{}, error) {
	if toa.DiscoveryDocument.UserinfoEndpoint == "" {
		return nil, errors.New("userinfo_endpoint is not set")
	}
	if toa.jwks() == nil {
		return nil, errors.New("OIDC discovery is not loaded yet")
	}

	resp, err := doWithRetries(toa.httpClient, maxRetries(toa.Config)+1, toa.logger, func() (*http.Request, error) {
		userinfoRequest, err := http.NewRequest("GET", toa.DiscoveryDocument.UserinfoEndpoint, nil)
		if err != nil {
			return nil, err
		}
		userinfoRequest.Header.Add("Authorization", "Bearer "+accessToken)
		return userinfoRequest, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New("token is not valid")
		}
		body, _ := io.ReadAll(resp.Body)
		toa.logger.Log(logging.LevelError, "getUserInfo: the provider answered HTTP %d", resp.StatusCode)
		toa.logger.Log(logging.LevelDebug, "getUserInfo: response body: %s", truncateForLog(string(body)))
		return nil, fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	var userInfoClaims map[string]interface{}

	switch {
	case strings.HasPrefix(contentType, "application/jwt"):
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		tokenString := string(body)

		claims := jwt.MapClaims{}

		err = toa.jwks().EnsureLoaded(toa.logger, toa.httpClient, false)
		if err != nil {
			return nil, err
		}

		options := []jwt.ParserOption{}

		if toa.Config.Provider.ValidateIssuerBool {
			options = append(options, jwt.WithIssuer(toa.issuer()))
		}

		parser := jwt.NewParser(options...)

		_, err = parser.ParseWithClaims(tokenString, claims, toa.jwks().Keyfunc)

		if err != nil {
			// If the token is expired, reloading JWKS won't help — skip the retry.
			if isTokenExpiredError(err) {
				toa.logger.Log(logging.LevelError, "Userinfo token is expired: %v", err)
				return nil, err
			}

			err := toa.jwks().EnsureLoaded(toa.logger, toa.httpClient, true)
			if err != nil {
				return nil, err
			}

			_, err = parser.ParseWithClaims(tokenString, claims, toa.jwks().Keyfunc)

			if err != nil {
				toa.logger.Log(logging.LevelError, "Failed to parse userinfo token: %v", err)
				return nil, err
			}
		}
		userInfoClaims = claims
	case strings.HasPrefix(contentType, "application/json"):
		err = json.NewDecoder(resp.Body).Decode(&userInfoClaims)
		if err != nil {
			toa.logger.Log(logging.LevelError, "getUserInfo: couldn't decode OidcTokenResponse: %s", err.Error())
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}

	userInfoSub, ok := userInfoClaims["sub"].(string)
	if !ok {
		toa.logger.Log(logging.LevelWarn, "getUserInfo: 'sub' claim in userinfo response is not a string or missing, discarding userinfo response")
		return map[string]interface{}{}, nil
	}

	if userInfoSub != idTokenSubject {
		toa.logger.Log(logging.LevelWarn, "getUserInfo: mismatch between 'sub' in userinfo response (%s) and 'sub' in id_token (%s), discarding userinfo response", userInfoSub, idTokenSubject)
		return map[string]interface{}{}, nil
	}

	return userInfoClaims, nil
}

// mergeClaims merges userinfo claims into token claims, preserving security-critical claims
func mergeClaims(tokenClaims, userInfoClaims map[string]interface{}) map[string]interface{} {
	// Create a copy of the token claims to avoid modifying the original
	mergedClaims := make(map[string]interface{})
	for key, value := range tokenClaims {
		mergedClaims[key] = value
	}

	// Define claims that should NOT be overwritten from userinfo
	protectedClaims := map[string]bool{
		"iss": true, // issuer
		"sub": true, // subject
		"aud": true, // audience
		"exp": true, // expiration time
		"iat": true, // issued at
		"nbf": true, // not before
		"jti": true, // JWT ID
		"azp": true, // authorized party
	}

	// Merge userinfo claims, skipping protected claims
	for key, value := range userInfoClaims {
		if !protectedClaims[key] {
			mergedClaims[key] = value
		}
	}

	return mergedClaims
}

// truncateForLog bounds an error body before it is written to the log: an
// identity provider error_description can echo request details.
func truncateForLog(body string) string {
	const maxLen = 256
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "..."
}
