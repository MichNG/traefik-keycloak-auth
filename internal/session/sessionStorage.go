package session

import (
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/google/uuid"
)

type SessionStorage interface {
	StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error)
	TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error)
}

// Revoker is implemented by the session stores that can delete a session from a
// back-channel logout token (which only carries the OIDC sid and sub).
type Revoker interface {
	RevokeBySid(sid string) (int, error)
	RevokeBySub(sub string) (int, error)
}

type SessionState struct {
	Id             string    `json:"id"`
	RefreshedAt    time.Time `json:"created_at"`
	AccessToken    string    `json:"access_token"`
	IdToken        string    `json:"id_token"`
	RefreshToken   string    `json:"refresh_token"`
	IsAuthorized   bool      `json:"is_authorized"`
	TokenExpiresIn int       `json:"token_expires_in"`

	// AuthenticatedAt is when the end-user authentication happened. It is used
	// to enforce the absolute `session.maxAge` limit, which does not move with
	// the activity nor with the token refresh. Zero means "unknown" and is
	// treated as RefreshedAt.
	AuthenticatedAt time.Time `json:"authenticated_at"`

	// OidcSid is the `sid` claim of the ID token (Keycloak session id), used to
	// revoke the session on a back-channel logout.
	OidcSid string `json:"oidc_sid,omitempty"`
	// Sub is the `sub` claim, the second back-channel logout matching key.
	Sub string `json:"sub,omitempty"`

	// Set when this session was (re-)established via a redirect triggered by UnauthorizedBehavior's
	// Challenge, regardless of whether the resulting session ends up authorized - the callback may be
	// handled by a different, more permissive middleware instance than the one that failed the check.
	// Used to avoid redirecting to the IDP again for the same session, which would otherwise risk an
	// infinite redirect loop.
	ChallengeAttempted bool `json:"challenge_attempted"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
