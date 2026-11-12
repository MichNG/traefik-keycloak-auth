package traefik_keycloak_auth

import (
	"strings"
	"testing"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/session"
)

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &config.Config{
		Provider: &config.ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionRefresh: true,
		SessionCookie: &config.SessionCookieConfig{
			MaxAge: 0,
		},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &TraefikOidcAuth{
		logger: logger,
		Config: config,
	}

	now := time.Now()

	sessionState := &session.SessionState{
		RefreshedAt:    now.Add(-29 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon := checkIdpTokenExpiresSoon(toa, sessionState)

	if expiresSoon {
		t.Fail()
	}

	sessionState = &session.SessionState{
		RefreshedAt:    now.Add(-30 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon = checkIdpTokenExpiresSoon(toa, sessionState)

	if !expiresSoon {
		t.Fail()
	}
}

func TestValidateToken_MissingToken(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Provider: &config.ProviderConfig{TokenValidation: "IdToken"},
		},
	}

	ok, _, err := toa.validateToken(&session.SessionState{AccessToken: "only-an-access-token"})

	if ok {
		t.Fatal("expected a session without an id token to be rejected")
	}

	if err == nil || !strings.Contains(err.Error(), "id_token") {
		t.Errorf("expected the error to name the missing token, got %v", err)
	}
}
