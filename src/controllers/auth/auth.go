// Package auth hosts the AuthController and the handlers it exposes.
// The controller is split across multiple files in this directory by
// feature:
//
//	auth.go              -- struct, constructor, loginUser, state helpers
//	ceremony.go          -- passkey ceremony store (putCeremony, takeCeremony, ...)
//	types.go             -- request and reply type definitions
//	helpers.go           -- passkey body/options/transports helpers
//	users.go             -- REST CRUD on users (PostUser, PatchUser, GetUser, Logout)
//	sessions.go          -- JWT access-token issuance (GetAccessToken, ...)
//	oauth_discord.go     -- Discord OAuth login flow
//	oauth_google.go      -- Google OAuth login flow
//	password.go          -- password login / signup (PostLogin, PostSignup)
//	link_oauth.go        -- popup-based OAuth account-linking flow
//	link_credentials.go  -- non-popup credential linking and management
//	passkey.go           -- passkey ceremonies (register, login, link)
//
// The controller still lives in `package controllers`; the directory
// is purely organisational.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"
)

// AuthController handles authentication logic. It dispatches the
// per-provider login flow to a strategy in the `auth` package and
// keeps the existing session-cookie plumbing for Discord. Passkey,
// password, and Google login go through the same `Login` entry point
// (`POST /auth/login`) by switching on the `kind` field of the
// request body.
type AuthController struct {
	OAuthConfig *oauth2.Config
	GoogleOAuth *oauth2.Config
	// OAuthLinkConfig is the OAuth config used by the popup-based
	// link flow (`/api/auth/link/discord/*`). It uses a separate
	// RedirectURL that points to the link callback. Nil when the
	// link OAuth is not configured; the link endpoints then
	// return 503 so the SPA can fall back to `POST /api/auth/link/<p>`.
	OAuthLinkConfig *oauth2.Config
	// GoogleLinkOAuth mirrors OAuthLinkConfig for Google.
	GoogleLinkOAuth *oauth2.Config

	// DiscordUserinfoURL is the absolute URL the Discord link
	// callback hits to fetch the user's profile after exchanging
	// the code. Defaults to https://discord.com/api/users/@me
	// when empty. Exposed so tests can redirect it at a mock
	// httptest server.
	DiscordUserinfoURL string
	// GoogleUserinfoURL is the equivalent for Google. Defaults to
	// https://openidconnect.googleapis.com/v1/userinfo.
	GoogleUserinfoURL string
	authService       auth.AuthServiceClientIface
	shareService      *proto.SharingServiceClient
	JWTSecret         string

	// webauthn runs the WebAuthn ceremony. Nil when RP ID is unset
	// (the six passkey endpoints then return 503).
	webauthn *webauthn.WebAuthn

	// ceremonyStore holds SessionData between /begin and /finish.
	ceremonyStore sync.Map
}

// passkeyCeremonyTTL bounds how long SessionData lasts in
// ceremonyStore between a /begin and its matching /finish.
const passkeyCeremonyTTL = 5 * time.Minute

// NewAuthController wires the controller. When rpID is empty the
// WebAuthn instance is left nil and the passkey endpoints return 503.
//
// The discordLinkOAuthConfig and googleLinkOAuthConfig are the OAuth
// configs used by the popup-based link flow. They typically share the
// ClientID / Secret / Endpoint of the login configs but use a separate
// RedirectURL that points at `/api/auth/link/<p>/callback`. When a
// link config is nil, the matching link endpoints return 503 and the
// SPA falls back to the existing `POST /api/auth/link/<p>` route.
func NewAuthController(
	discordOAuthConfig *oauth2.Config,
	googleOAuthConfig *oauth2.Config,
	authService auth.AuthServiceClientIface,
	shareService *proto.SharingServiceClient,
	jwtSecret string,
	rpID string,
	rpName string,
	rpOrigins []string,
	discordLinkOAuthConfig *oauth2.Config,
	googleLinkOAuthConfig *oauth2.Config,
) *AuthController {
	ac := &AuthController{
		OAuthConfig:     discordOAuthConfig,
		OAuthLinkConfig: discordLinkOAuthConfig,
		GoogleOAuth:     googleOAuthConfig,
		GoogleLinkOAuth: googleLinkOAuthConfig,
		authService:     authService,
		shareService:    shareService,
		JWTSecret:       jwtSecret,
	}
	if rpID != "" {
		w, err := webauthn.New(&webauthn.Config{
			RPID:          rpID,
			RPDisplayName: rpName,
			RPOrigins:     rpOrigins,
		})
		if err != nil {
			log.Printf("passkey: failed to build webauthn.Config: %v", err)
		} else {
			ac.webauthn = w
			go ac.cleanupCeremonies()
		}
	}
	return ac
}

// loginUser is the post-strategy hook that wires the verified user
// to a session cookie and returns a JWT. The strategy doesn't know
// about sessions or JWTs; only the controller does.
func (ac *AuthController) loginUser(c *gin.Context, user *proto.UserAuth) {
	session := sessions.Default(c)
	session.Set("user", &models.User{
		ID:    user.GetId(),
		Email: user.GetEmail(),
	})
	if err := session.Save(); err != nil {
		log.Printf("failed to save session: %v", err)
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to save session: %w", err))
		return
	}
	c.JSON(http.StatusOK, user.ParseJS())
}

// GenerateState creates a random state string for OAuth.
func (ac *AuthController) GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// webauthnConfigured reports whether the controller has a usable
// webauthn instance; callers map false -> 503.
func (ac *AuthController) webauthnConfigured() bool {
	return ac != nil && ac.webauthn != nil
}
