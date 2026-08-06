package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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
}

// NewAuthController creates a new auth controller.
func NewAuthController(
	discordOAuthConfig *oauth2.Config,
	googleOAuthConfig *oauth2.Config,
	authService auth.AuthServiceClientIface,
	shareService *proto.SharingServiceClient,
	jwtSecret string,
) *AuthController {
	return &AuthController{
		OAuthConfig:  discordOAuthConfig,
		GoogleOAuth:  googleOAuthConfig,
		authService:  authService,
		shareService: shareService,
		JWTSecret:    jwtSecret,
		Hasher:       auth.Argon2Hasher{},
	}
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
// and Google at /auth/google/*); this is for password and passkey.
type LoginRequest struct {
	Kind auth.Kind `json:"kind"`

	// Password fields
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"` // signup only

	// Passkey fields (verified by the controller via the WebAuthn
	// ceremony; the strategy just persists the result).
	CredentialId      []byte   `json:"credential_id,omitempty"`
	ClientDataJSON    []byte   `json:"client_data_json,omitempty"`
	AuthenticatorData []byte   `json:"authenticator_data,omitempty"`
	Signature         []byte   `json:"signature,omitempty"`
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
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to save session: %w", err))
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
	strategy := &auth.DiscordStrategy{
		Auth:          ac.authService,
		DiscordId:     int64(d_user.DiscordId),
		Username:      d_user.Username,
		Avatar:        d_user.Avatar,
		Email:         d_user.Email,
		Discriminator: d_user.Discriminator,
	}
	authUser, err := strategy.Login(c.Request.Context())
	if err != nil {
		log.Printf("Discord strategy login failed: %v", err)
		SetGinError(c, http.StatusServiceUnavailable, fmt.Errorf("gRPC service is unavailable: %w", err))
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
	user, _, err := UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	resp, err := ac.authService.GetUserAuth(c, &proto.GetUserAuthRequest{
		Identifier: &proto.GetUserAuthRequest_UserId{UserId: user.ID},
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch user via auth service: %w", err))
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
	user, status, err := UserFromContext(c)
	if user == nil {
		SetGinError(c, status, err)
		return
	}
	token, err := GenerateJWT(user.ID, ac.JWTSecret, nil)
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

	token, err := GenerateJWT(userId, ac.JWTSecret, unwrapNullableDatetime(resp.OnlineUntil))
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
	case auth.KindPasskeyKind:
		strategy = &auth.PasskeyLoginStrategy{
			Auth:              ac.authService,
			CredentialId:      req.CredentialId,
			ClientDataJSON:    req.ClientDataJSON,
			AuthenticatorData: req.AuthenticatorData,
			Signature:         req.Signature,
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
		if err == auth.InvalidPasskeyError {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		SetGinError(c, http.StatusInternalServerError, err)
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

	strategy := &auth.PasswordStrategy{
		Auth:     ac.authService,
		Hasher:   ac.Hasher,
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
		Signup:   true,
	}
	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		// ALREADY_EXISTS on the email -> 409.
		if status.Code(err) == codes.AlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
			return
		}
		SetGinError(c, http.StatusInternalServerError, err)
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
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("google code exchange failed: %w", err))
		return
	}
	client := ac.GoogleOAuth.Client(c, token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("google userinfo fetch failed: %w", err))
		return
	}
	defer resp.Body.Close()

	var gu struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gu); err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("google userinfo parse: %w", err))
		return
	}

	strategy := &auth.GoogleStrategy{
		Auth:          ac.authService,
		GoogleId:      gu.Sub,
		Email:         gu.Email,
		EmailVerified: gu.EmailVerified,
		Username:      gu.Name,
	}
	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		SetGinError(c, http.StatusServiceUnavailable, fmt.Errorf("google strategy login failed: %w", err))
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

// PostPasskeyRegisterBegin: 501 Not Implemented.
func (ac *AuthController) PostPasskeyRegisterBegin(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "passkey register begin requires WebAuthn ceremony store; not yet implemented"})
}

// PostPasskeyRegisterFinish: 501 Not Implemented.
func (ac *AuthController) PostPasskeyRegisterFinish(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "passkey register finish requires WebAuthn ceremony store; not yet implemented"})
}

// PostPasskeyLoginBegin: 501 Not Implemented.
func (ac *AuthController) PostPasskeyLoginBegin(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "passkey login begin requires WebAuthn ceremony store; not yet implemented"})
}

// PostPasskeyLoginFinish: 501 Not Implemented.
func (ac *AuthController) PostPasskeyLoginFinish(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "passkey login finish requires WebAuthn ceremony store; not yet implemented"})
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
	user, _, err := UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	discordId := c.Query("discord_id")
	if discordId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "discord_id is required"})
		return
	}
	_, err = ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId: user.ID,
		RequesterId: user.ID,
		Kind: proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
		Payload: &proto.LinkCredentialRequest_DiscordId{DiscordId: discordId},
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link discord failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": "discord"})
}

// PostLinkGoogle: link a google_id to the authenticated user.
func (ac *AuthController) PostLinkGoogle(c *gin.Context) {
	user, _, err := UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	googleId := c.Query("google_id")
	if googleId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "google_id is required"})
		return
	}
	_, err = ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId: user.ID,
		RequesterId: user.ID,
		Kind: proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
		Payload: &proto.LinkCredentialRequest_GoogleId{GoogleId: googleId},
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link google failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": "google"})
}

// PostLinkPassword: link a password to the authenticated user.
func (ac *AuthController) PostLinkPassword(c *gin.Context) {
	user, _, err := UserFromContext(c)
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
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	_, err = ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId: user.ID,
		RequesterId: user.ID,
		Kind: proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload: &proto.LinkCredentialRequest_PasswordHash{PasswordHash: hash},
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link password failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": "password"})
}

// PostLinkPasskeyBegin: 501 Not Implemented.
func (ac *AuthController) PostLinkPasskeyBegin(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "passkey linking requires WebAuthn ceremony store; not yet implemented"})
}

// PostLinkPasskeyFinish: 501 Not Implemented.
func (ac *AuthController) PostLinkPasskeyFinish(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "passkey linking requires WebAuthn ceremony store; not yet implemented"})
}

// GetLinkedCredentials returns the user's authenticated credentials
// summary (discord? password? N passkeys).
func (ac *AuthController) GetLinkedCredentials(c *gin.Context) {
	user, _, err := UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	resp, err := ac.authService.ListLinkedCredentials(c, &proto.ListLinkedCredentialsRequest{
		UserId: user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("list linked credentials failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"credentials": resp.GetCredentials(),
		"passkeys": resp.GetPasskeys(),
	})
}
