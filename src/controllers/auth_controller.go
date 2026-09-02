package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"

	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The Response of the GET /auth/access-token reply
type GetAccessTokenReply struct {
	Token string `json:"token"`
}

type PostAccessTokenRequest struct {
	// verify with the ID of a share
	ShareId string `json:"share_id"`
}

// AuthController handles authentication logic. It dispatches the
// per-provider login flow to a strategy in the `auth` package and
// keeps the existing session-cookie plumbing for Discord. Passkey,
// password, and Google login go through the same `Login` entry point
// (`POST /auth/login`) by switching on the `kind` field of the
// request body.
type AuthController struct {
	OAuthConfig  *oauth2.Config
	GoogleOAuth  *oauth2.Config
	authService  auth.AuthServiceClientIface
	shareService *proto.SharingServiceClient
	JWTSecret    string
	Hasher       auth.PasswordHasher

	// webauthn runs the WebAuthn ceremony. Nil when RP ID is unset
	// (the six passkey endpoints then return 503).
	webauthn *webauthn.WebAuthn

	// ceremonyStore holds SessionData between /begin and /finish.
	ceremonyStore sync.Map
}

const passkeyCeremonyTTL = 5 * time.Minute

type ceremonyEntry struct {
	data    webauthn.SessionData
	expires time.Time
}

// NewAuthController wires the controller. When rpID is empty the
// WebAuthn instance is left nil and the passkey endpoints return 503.
func NewAuthController(
	discordOAuthConfig *oauth2.Config,
	googleOAuthConfig *oauth2.Config,
	authService auth.AuthServiceClientIface,
	shareService *proto.SharingServiceClient,
	jwtSecret string,
	rpID string,
	rpName string,
	rpOrigins []string,
) *AuthController {
	ac := &AuthController{
		OAuthConfig:  discordOAuthConfig,
		GoogleOAuth:  googleOAuthConfig,
		authService:  authService,
		shareService: shareService,
		JWTSecret:    jwtSecret,
		Hasher:       auth.Argon2Hasher{},
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

// cleanupCeremonies evicts expired entries on a 1-minute ticker.
// sync.Map cannot delete-by-age, so the loop scans.
func (ac *AuthController) cleanupCeremonies() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		ac.ceremonyStore.Range(func(k, v any) bool {
			e, ok := v.(ceremonyEntry)
			if !ok || now.After(e.expires) {
				ac.ceremonyStore.Delete(k)
			}
			return true
		})
	}
}

// putCeremony stores SessionData under a random key.
func (ac *AuthController) putCeremony(sd webauthn.SessionData) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(nonce[:])
	ac.ceremonyStore.Store(key, ceremonyEntry{data: sd, expires: time.Now().Add(passkeyCeremonyTTL)})
	return key, nil
}

// takeCeremony loads and deletes; ok=false means unknown or expired.
func (ac *AuthController) takeCeremony(key string) (webauthn.SessionData, bool) {
	v, ok := ac.ceremonyStore.LoadAndDelete(key)
	if !ok {
		return webauthn.SessionData{}, false
	}
	e, ok := v.(ceremonyEntry)
	if !ok || time.Now().After(e.expires) {
		return webauthn.SessionData{}, false
	}
	return e.data, true
}

// webauthnConfigured reports whether the controller has a usable
// webauthn instance; callers map false -> 503.
func (ac *AuthController) webauthnConfigured() bool {
	return ac != nil && ac.webauthn != nil
}

// ------------ Login / signup requests -------------

type PasswordLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type PasswordSignupRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginRequest is the unified entry point for non-OAuth login flows.
// OAuth flows keep their dedicated routes (Discord at /auth/discord/*
// and Google at /auth/google/*); passkey login goes through the
// /auth/passkey/login/{begin,finish} endpoints, not here.
type LoginRequest struct {
	Kind auth.Kind `json:"kind"`

	// Password fields
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"` // signup only
}

// SignupRequest is the dedicated entry point for password signup.
// Splitting signup from login keeps the controller's branching
// explicit (signup is a separate code path on the gRPC side too).
type SignupRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
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

// GenerateState creates a random state string for OAuth
func (ac *AuthController) GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Login initiates Discord OAuth flow
func (ac *AuthController) Login(c *gin.Context) {
	state, err := ac.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	session := sessions.Default(c)
	session.Set("state", state)
	if err := session.Save(); err != nil {
		log.Printf("Save session failed: %v", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	url := ac.OAuthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Callback handles OAuth callback from Discord
func (ac *AuthController) Callback(c *gin.Context) {
	session := sessions.Default(c)
	savedState := session.Get("state")
	queryState := c.Query("state")

	if savedState == nil || savedState != queryState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	session.Delete("state")
	session.Save()

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
		return
	}

	token, err := ac.OAuthConfig.Exchange(c, code)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token. This could happen, because Discord Client ID or Client Secret is invalid"})
		return
	}

	client := ac.OAuthConfig.Client(c, token)
	resp, err := client.Get("https://discord.com/api/users/@me")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}
	defer resp.Body.Close()

	var d_user models.DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&d_user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user info"})
		return
	}

	// Hand the verified Discord profile to the strategy. The strategy
	// does the GetUserAuth -> CreateUserAuth dance and returns the
	// authenticated user. The controller doesn't know whether the
	// user existed before.
	discordAvatar := auth.DiscordAvatarURL(int64(d_user.DiscordId), d_user.Avatar)
	strategy := &auth.DiscordStrategy{
		Auth:          ac.authService,
		DiscordId:     int64(d_user.DiscordId),
		Username:      d_user.Username,
		Avatar:        d_user.Avatar,
		Email:         d_user.Email,
		Discriminator: d_user.Discriminator,
		AvatarUrl:     discordAvatar,
	}
	authUser, err := strategy.Login(c.Request.Context())
	if err != nil {
		log.Printf("Discord strategy login failed: %v", err)
		utils.SetGinError(c, http.StatusServiceUnavailable, fmt.Errorf("gRPC service is unavailable: %w", err))
		return
	}

	// Persist the Discord-shaped profile alongside the auth user so
	// the existing session keys (`DiscordId`, `Discriminator`,
	// `Avatar`) keep working across the rest of the app.
	user := models.User{
		ID:            authUser.GetId(),
		DiscordId:     models.Snowflake(d_user.DiscordId),
		Username:      d_user.Username,
		Discriminator: d_user.Discriminator,
		Avatar:        d_user.Avatar,
		Email:         d_user.Email,
	}
	session.Set("user", user)

	log.Printf("User %v logged in via Discord OAuth, gRPC ID: %v", d_user.Username, authUser.GetId())
	if err := session.Save(); err != nil {
		log.Printf("user: %v; Error: %v", d_user, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	redirect_url := fmt.Sprintf("%v", config.AppConfig.FrontendURL)
	c.Redirect(http.StatusTemporaryRedirect, redirect_url)
}

// GetUser returns the current authenticated user from the auth
// service. The session cookie carries the user id; the auth service
// returns the canonical UserAuth payload.
func (ac *AuthController) GetUser(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	resp, err := ac.authService.GetUserAuth(c, &proto.GetUserAuthRequest{
		Identifier: &proto.GetUserAuthRequest_UserId{UserId: user.ID},
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch user via auth service: %w", err))
		return
	}
	c.JSON(http.StatusOK, resp.GetUser().ParseJS())
}

// Logout clears the user session
func (ac *AuthController) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// generates a new JWT access token for an authenticated user
// GetAccessToken godoc
// @Summary      Get a new access token
// @Description  Generates a new JWT access token for the user authenticated via a session cookie.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  GetAccessTokenReply  "Successfully generated and returned access token"
// @Failure      401  {object}  map[string]string               "Unauthorized - User is not authenticated via session"
// @Failure      500  {object}  map[string]string               "Internal Server Error - Failed to generate JWT or other server-side issue"
// @Router       /auth/token [get]
func (ac *AuthController) GetAccessToken(c *gin.Context) {
	user, status, err := utils.UserFromContext(c)
	if user == nil {
		utils.SetGinError(c, status, err)
		return
	}
	token, err := utils.GenerateJWT(user.ID, ac.JWTSecret, nil)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	c.JSON(http.StatusOK, GetAccessTokenReply{
		Token: token,
	})
}

// generates a new JWT access token for an authenticated user
// GetAccessToken godoc
// @Summary      Get a new access token
// @Description  Generates a new JWT access token for the user authenticated via a session cookie.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  GetAccessTokenReply  "Successfully generated and returned access token"
// @Failure      401  {object}  map[string]string               "Unauthorized - User is not authenticated via session"
// @Failure      500  {object}  map[string]string               "Internal Server Error - Failed to generate JWT or other server-side issue"
// @Router       /auth/public-access-token [post]
func (ac *AuthController) GetPublicAccessToken(c *gin.Context) {
	// there is no user auth here

	var body PostAccessTokenRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Request the temp user behind the share
	resp, err := (*ac.shareService).GetShareUser(c, &proto.GetShareUserRequest{ShareId: body.ShareId})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid share ID"})
		return
	}
	userId := resp.AccessAs

	token, err := utils.GenerateJWT(userId, ac.JWTSecret, unwrapNullableDatetime(resp.OnlineUntil))
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	c.JSON(http.StatusOK, GetAccessTokenReply{
		Token: token,
	})
}

// ------------ New login flows -------------

// PostLogin handles non-OAuth login flows. The browser POSTs a
// `LoginRequest` with `kind: "password"` or `kind: "passkey"`. The
// controller dispatches to the matching strategy.
//
// OAuth flows (Discord, Google) keep their own /auth/<provider>/login
// routes so the browser can be redirected to the OAuth screen.
func (ac *AuthController) PostLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	kind, ok := auth.ResolveKind(string(req.Kind))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown login kind: " + string(req.Kind)})
		return
	}

	// For signin vs signup: signup is a separate route below. Login
	// is signin only.
	var strategy auth.LoginStrategy
	switch kind {
	case auth.KindPassword:
		if req.Email == "" || req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
			return
		}
		strategy = &auth.PasswordStrategy{
			Auth:     ac.authService,
			Hasher:   ac.Hasher,
			Email:    req.Email,
			Password: req.Password,
			Signup:   false,
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Login kind requires its own route: " + string(kind)})
		return
	}

	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		if err == auth.InvalidCredentialsError {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	ac.loginUser(c, user)
}

// PostSignup handles password signup. The body is a SignupRequest
// (email, username, password). On success, the user is logged in
// (session cookie is set) and the canonical UserAuth is returned.
func (ac *AuthController) PostSignup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}

	// Resolve the avatar *at signup time* so the user has something
	// to display from the very first request. Gravatar is the
	// fallback for password signups -- it'll either show the user's
	// actual Gravatar if they have one, or a generated identicon.
	gravatarAvatar := auth.GravatarURL(req.Email)

	strategy := &auth.PasswordStrategy{
		Auth:      ac.authService,
		Hasher:    ac.Hasher,
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		Signup:    true,
		AvatarUrl: gravatarAvatar,
	}
	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		// ALREADY_EXISTS on the email -> 409.
		if status.Code(err) == codes.AlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	ac.loginUser(c, user)
}

// ------------ Google OAuth -------------

// GoogleLogin initiates the Google OAuth flow. Mirrors the existing
// DiscordLogin handler, swapped to the GoogleOAuthConfig.
func (ac *AuthController) GoogleLogin(c *gin.Context) {
	if ac.GoogleOAuth == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Google OAuth is not configured"})
		return
	}
	state, err := ac.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}
	session := sessions.Default(c)
	session.Set("google_state", state)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, ac.GoogleOAuth.AuthCodeURL(state))
}

// GoogleCallback handles the OAuth callback from Google. The flow
// exchanges the code via the OAuth2 config, fetches the userinfo
// endpoint, and hands the verified profile to the GoogleStrategy.
func (ac *AuthController) GoogleCallback(c *gin.Context) {
	if ac.GoogleOAuth == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Google OAuth is not configured"})
		return
	}

	session := sessions.Default(c)
	savedState := session.Get("google_state")
	if savedState == nil || savedState != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}
	session.Delete("google_state")
	_ = session.Save()

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
		return
	}

	token, err := ac.GoogleOAuth.Exchange(c, code)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("google code exchange failed: %w", err))
		return
	}
	client := ac.GoogleOAuth.Client(c, token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("google userinfo fetch failed: %w", err))
		return
	}
	defer resp.Body.Close()

	var gu struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gu); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("google userinfo parse: %w", err))
		return
	}

	googleAvatar := auth.GoogleAvatarURL(gu.Picture)
	strategy := &auth.GoogleStrategy{
		Auth:          ac.authService,
		GoogleId:      gu.Sub,
		Email:         gu.Email,
		EmailVerified: gu.EmailVerified,
		Username:      gu.Name,
		AvatarUrl:     googleAvatar,
	}
	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		utils.SetGinError(c, http.StatusServiceUnavailable, fmt.Errorf("google strategy login failed: %w", err))
		return
	}
	ac.loginUser(c, user)
}

// ------------ Passkey ceremony endpoints (stubs) ------------
//
// These endpoints are stubs. The WebAuthn ceremony (challenge
// generation, attestation/assertion verification) belongs in REST
// because the gRPC backend was deliberately scoped to credential
// storage in the auth.proto. The ceremony result can be passed
// through to the gRPC backend once the `VerifyPasskey` RPC is
// implemented. Until then, the endpoints return 501.
//
// When the backend is ready, the controller will:
//
//   1. Generate a random challenge via crypto/rand.
//   2. Persist the challenge in a Redis store keyed by whether the
//      user is unauthenticated (login) or authenticated (linking).
//   3. Build the WebAuthn ceremony payload (rp, user, challenge,
//      allowCredentials/excludeCredentials) and return it.
//   4. On finish, retrieve the challenge, verify the browser's
//      response, and call AuthService.RegisterPasskey or update
//      the sign counter.

// PasskeyCeremonyBeginRequest kicks off a WebAuthn ceremony on the
// server. The body is optional.
//
// For the registration flow the caller MUST supply a UserId of an
// already-existing user -- passkey-only signup (no password) is not
// supported yet; the frontend should mint a password user via
// /auth/signup first, then attach a passkey via /auth/link/passkey.
// The login flow ignores the body entirely.
type PasskeyCeremonyBeginRequest struct {
	UserId string `json:"user_id,omitempty"`
}

// PasskeyCeremonyBeginReply is the response to a `/begin` endpoint.
// It carries the WebAuthn ceremony payload plus a server-generated
// `SessionKey` that the browser must echo back on the matching
// `/finish` call so the controller can look up the stored
// `SessionData` (challenge, allowed credentials, user handle).
type PasskeyCeremonyBeginReply struct {
	SessionKey string         `json:"session_key"`
	Options    map[string]any `json:"options"`
}

// PasskeyCeremonyFinishRequest is the body posted to the `/finish`
// endpoints. The browser includes:
//   - `session_key` from the matching /begin response,
//   - the raw attestation (registration) or assertion (login)
//     bytes the authenticator returned,
//   - for registration, an optional human-readable friendly_name
//     for the new passkey.
type PasskeyCeremonyFinishRequest struct {
	SessionKey        string `json:"session_key"`
	CredentialId      []byte `json:"credential_id"`
	ClientDataJSON    []byte `json:"client_data_json"`
	AuthenticatorData []byte `json:"authenticator_data"`
	Signature         []byte `json:"signature"`
	FriendlyName      string `json:"friendly_name,omitempty"`
}

// PasskeyCeremonyFinishReply is the success body returned by the
// `/finish` endpoints after a verified ceremony. The login variant
// returns the user via the session cookie + 200 with the parsed
// UserAuth body (kept consistent with `loginUser`).
type PasskeyCeremonyFinishReply struct {
	CredentialId string `json:"credential_id"`
}

// PostPasskeyRegisterBegin godoc
// @Summary      Begin a passkey registration ceremony
// @Description  Starts a WebAuthn registration ceremony for a new passkey.
// @Description
// @Description  The server generates a random challenge and returns the
// @Description  ceremony options (`PublicKeyCredentialCreationOptions`) that
// @Description  the browser uses to invoke the platform authenticator. The
// @Description  challenge is stored server-side and must be presented to
// @Description  the matching `/finish` endpoint for verification.
// @Description
// @Description  Returns 503 if passkey support is not configured
// @Description  (`WEBAUTHN_RP_ID` unset).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  PasskeyCeremonyBeginReply  "WebAuthn registration options"
// @Failure      400  {object}  map[string]string          "Bad Request - Invalid request body"
// @Failure      503  {object}  map[string]string          "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/register/begin [post]
func (ac *AuthController) PostPasskeyRegisterBegin(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyBeginRequest
	_ = c.ShouldBindJSON(&req) // body is optional
	user := &proto.UserAuth{Id: req.UserId}
	wu := auth.NewWebAuthnUser(user, nil)

	options, sessionData, err := ac.webauthn.BeginRegistration(wu)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("begin registration: %w", err))
		return
	}
	key, err := ac.putCeremony(*sessionData)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("store ceremony: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyBeginReply{
		SessionKey: key,
		Options:    ceremonyOptionsJSON(options.Response),
	})
}

// PostPasskeyRegisterFinish godoc
// @Summary      Finish a passkey registration ceremony
// @Description  Completes a WebAuthn registration ceremony started by
// @Description  `/auth/passkey/register/begin`.
// @Description
// @Description  The browser posts the attestation response
// @Description  (`credential_id`, `client_data_json`, `authenticator_data`,
// @Description  `signature`) and the `session_key` from the matching /begin.
// @Description  The server verifies the challenge, origin, RP ID, and
// @Description  attestation signature, then persists the credential via
// @Description  `AuthService.RegisterPasskey`. The User Handle supplied at
// @Description  /begin must already exist (see PostPasskeyRegisterBegin).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      PasskeyCeremonyFinishRequest  true  "WebAuthn attestation response"
// @Success      200      {object}  PasskeyCeremonyFinishReply   "Passkey registered"
// @Failure      400      {object}  map[string]string            "Bad Request - Invalid request body or expired ceremony"
// @Failure      401      {object}  map[string]string            "Unauthorized - Challenge mismatch or invalid attestation"
// @Failure      503      {object}  map[string]string            "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/register/finish [post]
func (ac *AuthController) PostPasskeyRegisterFinish(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	sessionData, ok := ac.takeCeremony(req.SessionKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ceremony expired or unknown"})
		return
	}
	userId := string(sessionData.UserID)
	if userId == "" || userId == "anonymous" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ceremony did not include a user id; use /auth/signup + /auth/link/passkey/{begin,finish} for first-time users"})
		return
	}
	wu, err := auth.LoadPasskeyUser(c.Request.Context(), ac.authService, userId)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("load user: %w", err))
		return
	}
	cred, err := ac.webauthn.FinishRegistration(wu, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("registration failed: %v", err)})
		return
	}
	if _, err := ac.authService.RegisterPasskey(c.Request.Context(), &proto.RegisterPasskeyRequest{
		UserId:         userId,
		RequesterId:    userId,
		CredentialId:   cred.ID,
		PublicKey:      cred.PublicKey,
		Transports:     authTransports(cred.Transport),
		Aaguid:         cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		UserVerified:   cred.Flags.UserVerified,
		FriendlyName:   req.FriendlyName,
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("register passkey: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyFinishReply{
		CredentialId: base64.RawURLEncoding.EncodeToString(cred.ID),
	})
}

// PostPasskeyLoginBegin godoc
// @Summary      Begin a passkey login ceremony
// @Description  Starts a WebAuthn assertion (login) ceremony.
// @Description
// @Description  The server generates a random challenge and returns the
// @Description  ceremony options (`PublicKeyCredentialRequestOptions`) for
// @Description  the browser. The challenge is stored server-side and must
// @Description  be presented to the matching `/finish` endpoint for
// @Description  verification. The flow is discoverable (no user identity
// @Description  required up front) -- the browser's authenticator selects
// @Description  which passkey to use and the User Handle is supplied with
// @Description  the assertion.
// @Description
// @Description  Returns 503 if passkey support is not configured.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  PasskeyCeremonyBeginReply  "WebAuthn assertion options"
// @Failure      503  {object}  map[string]string          "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/login/begin [post]
func (ac *AuthController) PostPasskeyLoginBegin(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	options, sessionData, err := ac.webauthn.BeginDiscoverableLogin()
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("begin login: %w", err))
		return
	}
	key, err := ac.putCeremony(*sessionData)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("store ceremony: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyBeginReply{
		SessionKey: key,
		Options:    ceremonyOptionsJSON(options.Response),
	})
}

// PostPasskeyLoginFinish godoc
// @Summary      Finish a passkey login ceremony
// @Description  Completes a WebAuthn assertion (login) ceremony started by
// @Description  `/auth/passkey/login/begin`.
// @Description
// @Description  The browser posts the assertion (`credential_id`,
// @Description  `client_data_json`, `authenticator_data`, `signature`) and
// @Description  the `session_key` from the matching /begin. The server
// @Description  resolves the user from the User Handle, verifies the
// @Description  signature against the stored public key, bumps the sign
// @Description  counter via `AuthService.UpdatePasskeyCounter`, and logs
// @Description  the user in.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      PasskeyCeremonyFinishRequest  true  "WebAuthn assertion response"
// @Success      200      {object}  models.JsUserAuth            "Login successful - session cookie set"
// @Failure      400      {object}  map[string]string            "Bad Request - Invalid request body or expired ceremony"
// @Failure      401      {object}  map[string]string            "Unauthorized - Challenge mismatch, invalid signature, or unknown credential"
// @Failure      503      {object}  map[string]string            "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/login/finish [post]
func (ac *AuthController) PostPasskeyLoginFinish(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	sessionData, ok := ac.takeCeremony(req.SessionKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ceremony expired or unknown"})
		return
	}
	var matched *auth.WebAuthnUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		wu, err := auth.WebAuthnUserResolver(c.Request.Context(), ac.authService)(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		resolved, ok := wu.(*auth.WebAuthnUser)
		if !ok {
			return wu, nil
		}
		matched = resolved
		return resolved, nil
	}
	_, cred, err := ac.webauthn.FinishPasskeyLogin(handler, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("login failed: %v", err)})
		return
	}
	if matched == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "could not resolve passkey owner"})
		return
	}
	rec := matched.FindCredential(cred.ID)
	if rec == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "matched passkey not in user's credential list"})
		return
	}
	if _, err := ac.authService.UpdatePasskeyCounter(c.Request.Context(), &proto.UpdatePasskeyCounterRequest{
		PasskeyId:    rec.PasskeyID,
		NewSignCount: uint64(cred.Authenticator.SignCount),
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("update counter: %w", err))
		return
	}
	ac.loginUser(c, matched.UserAuth)
}

// authTransports converts the typed webauthn transport list back to
// strings for the gRPC `repeated string` field.
func authTransports(in []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

// ceremonyOptionsJSON round-trips a webauthn options struct through
// encoding/json so gin's encoder can serialize it generically.
func ceremonyOptionsJSON(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// ------------ Account linking ------------
//
// Linking takes an authenticated user and attaches a new credential
// to their account. Each endpoint mirrors the corresponding login
// flow but skips the user-creation step and uses the gRPC
// `LinkCredential` RPC (with the existing user's id as the
// `requester_id`).

type LinkPasswordRequest struct {
	Password string `json:"password"`
}

// PostLinkDiscord: link a discord_id to the authenticated user.
// The discord_id is supplied as a query parameter (?discord_id=...
// &username=... &avatar=...). The controller passes the values to
// the gRPC backend via AuthService.LinkCredential.
func (ac *AuthController) PostLinkDiscord(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	discordId := c.Query("discord_id")
	avatarHash := c.Query("avatar_hash")
	if discordId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "discord_id is required"})
		return
	}
	did, err := strconv.ParseInt(discordId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "discord_id must be an integer"})
		return
	}
	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
		Payload:     &proto.LinkCredentialRequest_DiscordId{DiscordId: discordId},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link discord failed: %w", err))
		return
	}

	// Refresh the avatar with the new Discord provider. The
	// frontend should call this with the latest Discord profile
	// data after the OAuth dance.
	if avatarURL := auth.DiscordAvatarURL(did, avatarHash); avatarURL != "" {
		if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
			UserId:      user.ID,
			RequesterId: user.ID,
			AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
				AvatarUrlSet: avatarURL,
			},
		}); err != nil {
			// Non-fatal: the credential is linked, but the avatar
			// didn't update. The frontend will see the old avatar
			// until the next refresh.
			log.Printf("link discord: avatar update failed: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"linked": "discord"})
}

// PostLinkGoogle: link a google_id to the authenticated user.
func (ac *AuthController) PostLinkGoogle(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	googleId := c.Query("google_id")
	picture := c.Query("picture")
	if googleId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "google_id is required"})
		return
	}
	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
		Payload:     &proto.LinkCredentialRequest_GoogleId{GoogleId: googleId},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link google failed: %w", err))
		return
	}

	// Refresh the avatar with the new Google provider. The frontend
	// should call this with the latest Google userinfo data after
	// the OAuth dance.
	if avatarURL := auth.GoogleAvatarURL(picture); avatarURL != "" {
		if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
			UserId:      user.ID,
			RequesterId: user.ID,
			AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
				AvatarUrlSet: avatarURL,
			},
		}); err != nil {
			log.Printf("link google: avatar update failed: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"linked": "google"})
}

// PostLinkPassword: link a password to the authenticated user.
func (ac *AuthController) PostLinkPassword(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req LinkPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
		return
	}
	hash, err := ac.Hasher.Hash(req.Password)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	_, err = ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload:     &proto.LinkCredentialRequest_PasswordHash{PasswordHash: hash},
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link password failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": "password"})
}

// PostLinkPasskeyBegin godoc
// @Summary      Begin linking a passkey to the authenticated account
// @Description  Starts a WebAuthn registration ceremony for the currently
// @Description  authenticated user. The challenge is keyed against the
// @Description  user's session so it cannot be replayed against a
// @Description  different account.
// @Description
// @Description  The server returns ceremony options
// @Description  (`PublicKeyCredentialCreationOptions`) that the browser
// @Description  uses to invoke the platform authenticator.
// @Description
// @Description  Returns 503 if passkey support is not configured.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  PasskeyCeremonyBeginReply  "WebAuthn registration options"
// @Failure      401  {object}  map[string]string          "Unauthorized - User is not authenticated via session"
// @Failure      503  {object}  map[string]string          "Service Unavailable - Passkey support not configured"
// @Router       /auth/link/passkey/begin [post]
func (ac *AuthController) PostLinkPasskeyBegin(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	wu, err := auth.LoadPasskeyUser(c.Request.Context(), ac.authService, user.ID)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("load user: %w", err))
		return
	}
	// Exclude the user's existing credentials so the picker hides them.
	creds := webauthn.Credentials(wu.WebAuthnCredentials())
	options, sessionData, err := ac.webauthn.BeginRegistration(wu,
		webauthn.WithExclusions(creds.CredentialDescriptors()),
	)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("begin registration: %w", err))
		return
	}
	key, err := ac.putCeremony(*sessionData)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("store ceremony: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyBeginReply{
		SessionKey: key,
		Options:    ceremonyOptionsJSON(options.Response),
	})
}

// PostLinkPasskeyFinish godoc
// @Summary      Finish linking a passkey to the authenticated account
// @Description  Completes a WebAuthn registration ceremony started by
// @Description  `/auth/link/passkey/begin`, attaching the verified passkey
// @Description  to the currently authenticated user via
// @Description  `AuthService.RegisterPasskey`.
// @Description
// @Description  The browser posts the attestation response
// @Description  (`credential_id`, `client_data_json`, `authenticator_data`,
// @Description  `signature`) and the `session_key` from the matching /begin.
// @Description  The server verifies the challenge, origin, RP ID, and
// @Description  attestation signature, then persists the credential via
// @Description  `AuthService.RegisterPasskey` with the authenticated user
// @Description  as both `user_id` and `requester_id`.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      PasskeyCeremonyFinishRequest  true  "WebAuthn attestation response"
// @Success      200      {object}  PasskeyCeremonyFinishReply   "Passkey linked to account"
// @Failure      400      {object}  map[string]string            "Bad Request - Invalid request body or malformed attestation"
// @Failure      401      {object}  map[string]string            "Unauthorized - User is not authenticated, or challenge mismatch"
// @Failure      503      {object}  map[string]string            "Service Unavailable - Passkey support not configured"
// @Router       /auth/link/passkey/finish [post]
func (ac *AuthController) PostLinkPasskeyFinish(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	sessionData, ok := ac.takeCeremony(req.SessionKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ceremony expired or unknown"})
		return
	}
	wu, err := auth.LoadPasskeyUser(c.Request.Context(), ac.authService, user.ID)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("load user: %w", err))
		return
	}
	cred, err := ac.webauthn.FinishRegistration(wu, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("registration failed: %v", err)})
		return
	}
	if _, err := ac.authService.RegisterPasskey(c.Request.Context(), &proto.RegisterPasskeyRequest{
		UserId:         user.ID,
		RequesterId:    user.ID,
		CredentialId:   cred.ID,
		PublicKey:      cred.PublicKey,
		Transports:     authTransports(cred.Transport),
		Aaguid:         cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		UserVerified:   cred.Flags.UserVerified,
		FriendlyName:   req.FriendlyName,
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("register passkey: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyFinishReply{
		CredentialId: base64.RawURLEncoding.EncodeToString(cred.ID),
	})
}

// GetLinkedCredentials returns the user's authenticated credentials
// summary (discord? password? N passkeys).
func (ac *AuthController) GetLinkedCredentials(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	resp, err := ac.authService.ListLinkedCredentials(c, &proto.ListLinkedCredentialsRequest{
		UserId: user.ID,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("list linked credentials failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"credentials": resp.GetCredentials(),
		"passkeys":    resp.GetPasskeys(),
	})
}
