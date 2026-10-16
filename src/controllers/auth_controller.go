package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	authService     auth.AuthServiceClientIface
	shareService    *proto.SharingServiceClient
	JWTSecret       string

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

// LoginRequest is the body of POST /api/auth/login. Today the
// controller only accepts `kind: "password"`; passkey login goes
// through the /auth/passkey/login/{begin,finish} endpoints and
// OAuth flows (Discord, Google) keep their dedicated routes.
//
// The password is sent in plaintext over the wire (HTTPS in front)
// and hashed server-side before reaching gRPC.
type LoginRequest struct {
	Kind auth.Kind `json:"kind" example:"password"`

	// Password fields
	Email    string `json:"email,omitempty" example:"alice@example.com"`
	Password string `json:"password,omitempty" example:"correct horse battery staple"`
}

// SignupRequest is the body of POST /api/auth/signup. Splitting
// signup from login keeps the controller's branching explicit
// (signup is a separate code path on the gRPC side too).
type SignupRequest struct {
	Email    string `json:"email" example:"alice@example.com"`
	Username string `json:"username" example:"alice"`
	Password string `json:"password" example:"correct horse battery staple"`
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

// ------------ REST CRUD: /api/users -------------

// PostUserRequest is the body for POST /api/users: clients send a
// plaintext password, the server hashes it server-side before
// reaching the auth gRPC service.
type PostUserRequest struct {
	Email     string `json:"email" binding:"required" example:"alice@example.com"`
	Username  string `json:"username" binding:"required" example:"alice"`
	Password  string `json:"password" binding:"required" example:"correct horse battery staple"`
	AvatarURL string `json:"avatar_url,omitempty" example:"https://cdn.example.com/avatars/alice.png"`
}

// PatchUserRequest is the body for PATCH /api/users/:id: each field
// is tri-state (omit / set / clear) and set+clear is rejected as 400.
type PatchUserRequest struct {
	Username             *string    `json:"username,omitempty" example:"alice"`
	UsernameClear        bool       `json:"username_clear,omitempty" example:"false"`
	Email                *string    `json:"email,omitempty" example:"alice@example.com"`
	EmailClear           bool       `json:"email_clear,omitempty" example:"false"`
	EmailVerifiedAt      *time.Time `json:"email_verified_at,omitempty" example:"2026-10-12T10:00:00Z"`
	EmailVerifiedAtClear bool       `json:"email_verified_at_clear,omitempty" example:"false"`
	AvatarURL            *string    `json:"avatar_url,omitempty" example:"https://cdn.example.com/avatars/alice.png"`
	AvatarURLClear       bool       `json:"avatar_url_clear,omitempty" example:"false"`
}

// PostUser godoc
// @Summary      Create a user
// @Description  Creates a user via the auth gRPC service. The client
// @Description  sends a plaintext password; the server hashes it
// @Description  (argon2id) before reaching gRPC. Unlike POST
// @Description  /api/auth/signup, this endpoint does not set a session
// @Description  cookie, so it is safe for admin-issued or import flows.
// @Description
// @Description  Returns 409 on a duplicate email and 400 on missing
// @Description  fields or an invalid argument from gRPC.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        payload  body      PostUserRequest  true  "New user payload"
// @Success      200      {object}  models.JsUserAuth             "Created user"
// @Failure      400      {object}  map[string]string              "Bad Request - missing fields or invalid argument"
// @Failure      409      {object}  map[string]string              "Conflict - email already in use"
// @Failure      500      {object}  map[string]string              "Internal Server Error - gRPC service failure"
// @Router       /api/users [post]
func (ac *AuthController) PostUser(c *gin.Context) {
	var req PostUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Email == "" || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, username, and password are required"})
		return
	}

	hash, err := auth.Argon2Hasher{}.Hash(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := ac.authService.CreateUserAuth(c, &proto.CreateUserAuthRequest{
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: hash,
		AvatarUrl:    req.AvatarURL,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.AlreadyExists:
			c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
			return
		case codes.InvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("create user: %w", err))
		return
	}
	c.JSON(http.StatusOK, resp.GetUser().ParseJS())
}

// PatchUser godoc
// @Summary      Partially update a user
// @Description  Applies a tri-state update (omit / set / clear) to one or
// @Description  more mutable fields on the user identified by `:id`. The
// @Description  actor for the gRPC permission check is the authenticated
// @Description  session user; supplying both `field` and `field_clear` for
// @Description  the same key is rejected as 400.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        id       path      string            true  "User ID (UUIDv7)"
// @Param        payload  body      PatchUserRequest  true  "Partial update payload"
// @Success      200      {object}  models.JsUserAuth             "Updated user"
// @Failure      400      {object}  map[string]string              "Bad Request - invalid id, bad JSON, or set/clear conflict"
// @Failure      401      {object}  map[string]string              "Unauthorized - no session or JWT"
// @Failure      403      {object}  map[string]string              "Forbidden - actor may not edit this user"
// @Failure      404      {object}  map[string]string              "Not Found - user does not exist"
// @Failure      500      {object}  map[string]string              "Internal Server Error - gRPC service failure"
// @Router       /api/users/{id} [patch]
func (ac *AuthController) PatchUser(c *gin.Context) {
	userID, code, err := utils.GetIdFromURL(c, "id")
	if err != nil {
		utils.SetGinError(c, code, err)
		return
	}
	actor, actorCode, err := utils.UserFromContext(c)
	if actor == nil {
		utils.SetGinError(c, actorCode, err)
		return
	}

	var req PatchUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if (req.Username != nil) && req.UsernameClear {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username: set and clear are mutually exclusive"})
		return
	}
	if (req.Email != nil) && req.EmailClear {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email: set and clear are mutually exclusive"})
		return
	}
	if (req.EmailVerifiedAt != nil) && req.EmailVerifiedAtClear {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email_verified_at: set and clear are mutually exclusive"})
		return
	}
	if (req.AvatarURL != nil) && req.AvatarURLClear {
		c.JSON(http.StatusBadRequest, gin.H{"error": "avatar_url: set and clear are mutually exclusive"})
		return
	}

	upd := &proto.UpdateUserAuthRequest{
		UserId:      userID,
		RequesterId: actor.ID,
	}
	if req.Username != nil {
		upd.UsernameChange = &proto.UpdateUserAuthRequest_UsernameSet{UsernameSet: *req.Username}
	} else if req.UsernameClear {
		upd.UsernameChange = &proto.UpdateUserAuthRequest_UsernameClear{UsernameClear: &emptypb.Empty{}}
	}
	if req.Email != nil {
		upd.EmailChange = &proto.UpdateUserAuthRequest_EmailSet{EmailSet: *req.Email}
	} else if req.EmailClear {
		upd.EmailChange = &proto.UpdateUserAuthRequest_EmailClear{EmailClear: &emptypb.Empty{}}
	}
	if req.EmailVerifiedAt != nil {
		upd.EmailVerifiedChange = &proto.UpdateUserAuthRequest_EmailVerifiedAtSet{
			EmailVerifiedAtSet: timestamppb.New(*req.EmailVerifiedAt),
		}
	} else if req.EmailVerifiedAtClear {
		upd.EmailVerifiedChange = &proto.UpdateUserAuthRequest_EmailVerifiedAtClear{EmailVerifiedAtClear: &emptypb.Empty{}}
	}
	if req.AvatarURL != nil {
		upd.AvatarUrlChange = &proto.UpdateUserAuthRequest_AvatarUrlSet{AvatarUrlSet: *req.AvatarURL}
	} else if req.AvatarURLClear {
		upd.AvatarUrlChange = &proto.UpdateUserAuthRequest_AvatarUrlClear{AvatarUrlClear: &emptypb.Empty{}}
	}

	resp, err := ac.authService.UpdateUserAuth(c, upd)
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		case codes.PermissionDenied:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		case codes.InvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("update user: %w", err))
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

// PostLogin godoc
// @Summary      Sign in with a password
// @Description  Authenticates an existing user via password. The client
// @Description  sends a plaintext password; the server hashes it
// @Description  (argon2id) before comparing to the stored hash. On
// @Description  success, a session cookie is set and the canonical
// @Description  UserAuth is returned.
// @Description
// @Description  Passkey login uses the dedicated
// @Description  /auth/passkey/login/{begin,finish} endpoints instead.
// @Description  OAuth flows (Discord, Google) keep their own
// @Description  /auth/<provider>/login routes so the browser can be
// @Description  redirected to the provider.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      LoginRequest  true  "Login payload (kind: \"password\")"
// @Success      200      {object}  models.JsUserAuth  "Login successful - session cookie set"
// @Failure      400      {object}  map[string]string   "Bad Request - Invalid body, unknown kind, or missing fields"
// @Failure      401      {object}  map[string]string   "Unauthorized - Invalid credentials"
// @Failure      500      {object}  map[string]string   "Internal Server Error - gRPC service failure"
// @Router       /api/auth/login [post]
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

// PostSignup godoc
// @Summary      Sign up with a password
// @Description  Creates a new user via password signup. The client
// @Description  sends a plaintext password; the server hashes it
// @Description  (argon2id) before reaching gRPC. On success, a session
// @Description  cookie is set and the canonical UserAuth is returned.
// @Description
// @Description  Returns 409 if the email is already in use.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      SignupRequest  true  "Signup payload"
// @Success      200      {object}  models.JsUserAuth  "User created and signed in - session cookie set"
// @Failure      400      {object}  map[string]string   "Bad Request - Invalid body or missing fields"
// @Failure      409      {object}  map[string]string   "Conflict - Email already in use"
// @Failure      500      {object}  map[string]string   "Internal Server Error - gRPC service failure"
// @Router       /api/auth/signup [post]
func (ac *AuthController) PostSignup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Email == "" || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, username, and password are required"})
		return
	}

	gravatarAvatar := auth.GravatarURL(req.Email)

	strategy := &auth.PasswordStrategy{
		Auth:      ac.authService,
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

// ------------ Popup-based account linking ------------
//
// `GET /api/auth/link/:p/init` opens an OAuth dance in a popup so the
// SPA can drive a Discord / Google link without leaving the Settings
// page. The init endpoint generates a CSRF state, stores it in the
// session, and 302s to the provider. The callback endpoint verifies
// the state, exchanges the code, and calls `LinkCredential` on the
// *currently authenticated* user (instead of the login strategy which
// creates users). It then 302s to `/api/auth/link/:p/complete?payload=…`
// which serves a tiny HTML page that posts the payload to `window.opener`.
//
// The session cookie is shared between the popup and the main window
// (SameSite=Lax allows top-level navigations to send it), so the
// session doubles as the auth token AND the CSRF store. The state keys
// (`link_state_discord`, `link_state_google`) are namespaced to avoid
// colliding with the regular login flow's `state` / `google_state`.
//
// If the popup is lost (closed by user, blocked by browser), the SPA
// falls back to `POST /api/auth/link/<p>?<provider>_id=…` which is
// unchanged.

// linkStateKey returns the session key used to store the OAuth state
// for a link flow. Provider-scoped so simultaneous flows on different
// providers don't collide.
func linkStateKey(p string) string { return "link_state_" + p }

// linkOAuthFor returns the OAuth config and credential kind for a
// link flow. ok=false means the provider is unknown OR the link OAuth
// is not configured for that provider; callers map false -> 503.
func (ac *AuthController) linkOAuthFor(p string) (*oauth2.Config, proto.CredentialKind, bool) {
	switch p {
	case "discord":
		if ac.OAuthLinkConfig == nil {
			return nil, 0, false
		}
		return ac.OAuthLinkConfig, proto.CredentialKind_CREDENTIAL_KIND_DISCORD, true
	case "google":
		if ac.GoogleLinkOAuth == nil {
			return nil, 0, false
		}
		return ac.GoogleLinkOAuth, proto.CredentialKind_CREDENTIAL_KIND_GOOGLE, true
	}
	return nil, 0, false
}

// encodeLinkPayload serializes a payload map to a URL-safe base64
// string. The complete endpoint embeds it in `?payload=…` and the
// HTML page decodes it before posting to the SPA.
func encodeLinkPayload(payload map[string]any) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// decodeLinkPayload parses the `payload` query parameter. ok=false
// means the payload is missing or malformed.
func decodeLinkPayload(s string) (map[string]any, bool) {
	if s == "" {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false
	}
	return out, true
}

// frontendOrigin extracts the origin (scheme://host[:port]) from
// FrontendURL. Falls back to the raw value when the URL doesn't
// parse cleanly; the popup HTML page only uses it for postMessage
// targetOrigin so an empty/malformed value becomes a literal "*"
// after the parse fails.
func frontendOrigin(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// linkCompleteHTML is the tiny HTML page that the popup serves after
// a link callback completes. It decodes the `payload` query string
// and posts it to `window.opener` so the SPA can react (close the
// popup, refresh the linked-credentials list, show a toast).
//
// When `window.opener` is missing (popup opened in a new tab, parent
// navigated, popup blocker closed the parent), the payload is
// rendered into the body so the user can copy the result manually.
// The SPA's fallback flow (`POST /api/auth/link/<p>`) handles the
// common "opener closed" case.
const linkCompleteHTMLTmpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Link complete</title>
<style>body{font-family:system-ui,sans-serif;padding:1.5rem;color:#222}</style>
</head>
<body>
<p>You can close this window.</p>
<pre id="payload" style="white-space:pre-wrap;word-break:break-all"></pre>
<script>
(function() {
  var params = new URLSearchParams(window.location.search);
  var raw = params.get('payload') || '';
  var data;
  try { data = JSON.parse(atob(raw)); }
  catch (err) {
    document.getElementById('payload').textContent = 'bad payload: ' + err.message;
    return;
  }
  document.getElementById('payload').textContent = JSON.stringify(data, null, 2);
  data.type = 'auth-link-complete';
  if (window.opener) {
    try {
      window.opener.postMessage(data, %q);
      window.close();
    } catch (err) {
      document.body.insertAdjacentHTML('afterbegin',
        '<p>postMessage failed: ' + err.message + '</p>');
    }
  }
})();
</script>
</body>
</html>
`

// GetLinkInit godoc
// @Summary      Start an OAuth link flow in a popup
// @Description  Browser-driven entry point for the OAuth account-linking
// @Description  flow used by the SPA's Security page. The SPA opens a
// @Description  popup to `GET /api/auth/link/{provider}/init`, which:
// @Description  1. Requires an active session cookie (the popup and the
// @Description     main window share the same session).
// @Description  2. Generates a CSRF `state` and stores it under the
// @Description     provider-scoped session key, bound to the current
// @Description     user id so the matching /callback cannot link into
// @Description     a different account.
// @Description  3. 302-redirects the popup to the provider's authorize
// @Description     URL with that `state` as the `state` query parameter.
// @Description
// @Description  Returns 503 when the link OAuth is not configured for
// @Description  the provider (operator did not set the matching
// @Description  `*_LINK_REDIRECT_URI` env var). When the SPA sees 503
// @Description  it falls back to the non-popup route:
// @Description  `POST /api/auth/link/discord` or
// @Description  `POST /api/auth/link/google` (literal paths, not
// @Description  templated).
// @Tags         Authentication
// @Produce      json
// @Security     CookieAuth
// @Param        p  path  string  true  "Provider: discord or google"
// @Success      307  "Redirect to provider authorize URL"
// @Failure      401  {object}  map[string]string  "Unauthorized - no session"
// @Failure      503  {object}  map[string]string  "Service Unavailable - link OAuth not configured for this provider"
// @Router       /auth/link/{p}/init [get]
func (ac *AuthController) GetLinkInit(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if user == nil {
		utils.SetGinError(c, code, err)
		return
	}
	p := c.Param("p")
	cfg, _, ok := ac.linkOAuthFor(p)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": fmt.Sprintf("OAuth linking for %q is not configured", p),
		})
		return
	}

	state, err := ac.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}
	session := sessions.Default(c)
	session.Set(linkStateKey(p), state)
	// Bind the state to the current user so a callback from a
	// different session can't link into this user's account.
	session.Set(linkStateKey(p)+"_user", user.ID)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, cfg.AuthCodeURL(state))
}

// GetLinkCallback godoc
// @Summary      OAuth link callback (server-side)
// @Description  Server-side endpoint the OAuth provider redirects to
// @Description  after the user finishes the popup-based link flow.
// @Description  This endpoint never returns JSON; it only:
// @Description  1. Verifies the CSRF `state` against the one stored in
// @Description     the session during /init, and confirms the session
// @Description     user still matches the user bound to that state.
// @Description  2. Exchanges the `code` against the provider's token
// @Description     endpoint.
// @Description  3. Fetches the provider's userinfo and calls
// @Description     `AuthService.LinkCredential` against the currently
// @Description     authenticated user (no new user is ever created).
// @Description  4. If the provider returned an avatar URL, refreshes
// @Description     the user's `avatar_url`.
// @Description  5. 302-redirects the popup to
// @Description     `/api/auth/link/{provider}/complete?payload=…`,
// @Description     where the payload is a base64url-encoded JSON
// @Description     object the SPA's main window receives via
// @Description     `postMessage`.
// @Description
// @Description  On any error in steps 1-4 the response is still a 307
// @Description  to /complete with an error payload (so the SPA can
// @Description  surface a toast instead of staring at a closed popup),
// @Description  EXCEPT for: missing `code` or state mismatch (400),
// @Description  no session (401), or link OAuth not configured (503).
// @Description
// @Description  Note: `LinkCredential` returns ALREADY_EXISTS when the
// @Description  provider id is already linked to a different user
// @Description  account. The callback surfaces this as an error
// @Description  payload on /complete; the SPA should refresh its
// @Description  linked-credentials list and show the failure.
// @Tags         Authentication
// @Produce      json
// @Security     CookieAuth
// @Param        p      path   string  true   "Provider: discord or google"
// @Param        code   query  string  true   "Authorization code returned by the provider"
// @Param        state  query  string  true   "CSRF state echoed from /init"
// @Success      307  "Redirect to /complete?payload=… (success or error payload)"
// @Failure      400  {object}  map[string]string  "Bad Request - missing code, state mismatch, or state bound to a different user"
// @Failure      401  {object}  map[string]string  "Unauthorized - no session"
// @Failure      500  {object}  map[string]string  "Internal Server Error - code exchange / userinfo failure when /complete cannot be reached"
// @Failure      503  {object}  map[string]string  "Service Unavailable - link OAuth not configured for this provider"
// @Router       /auth/link/{p}/callback [get]
func (ac *AuthController) GetLinkCallback(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if user == nil {
		utils.SetGinError(c, code, err)
		return
	}
	p := c.Param("p")
	cfg, kind, ok := ac.linkOAuthFor(p)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": fmt.Sprintf("OAuth linking for %q is not configured", p),
		})
		return
	}

	session := sessions.Default(c)
	savedState, _ := session.Get(linkStateKey(p)).(string)
	if savedState == "" || savedState != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}
	savedUser, _ := session.Get(linkStateKey(p) + "_user").(string)
	session.Delete(linkStateKey(p))
	session.Delete(linkStateKey(p) + "_user")
	_ = session.Save()
	if savedUser != "" && savedUser != user.ID {
		// The state was minted for a different session user.
		// Reject so a flow started by user A can't link into B.
		c.JSON(http.StatusBadRequest, gin.H{"error": "state does not match session user"})
		return
	}

	codeStr := c.Query("code")
	if codeStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
		return
	}

	token, err := cfg.Exchange(c, codeStr)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError,
			fmt.Errorf("%s code exchange failed: %w", p, err))
		return
	}

	// Build the postMessage payload. Errors during the link dance
	// still serve the complete page so the SPA can react to a
	// failure instead of staring at a closed popup.
	payload, linkErr := ac.linkFromOAuth(c, p, kind, cfg, token, user.ID)
	if linkErr != nil {
		log.Printf("link %s: %v", p, linkErr)
		payload = map[string]any{
			"provider": p,
			"error":    linkErr.Error(),
		}
	}
	encoded, err := encodeLinkPayload(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode payload"})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, "/api/auth/link/"+p+"/complete?payload="+encoded)
}

// linkFromOAuth runs the provider-specific part of the link callback:
// fetches the provider profile, calls LinkCredential against the
// currently authenticated user, optionally refreshes the avatar,
// and returns the postMessage payload.
//
// Errors are returned with enough context for the caller to log them;
// the payload sent to the SPA on success contains `provider`, `id`,
// `username`, and (for Discord) `avatar` / (for Google) `picture`.
func (ac *AuthController) linkFromOAuth(
	c *gin.Context,
	p string,
	kind proto.CredentialKind,
	cfg *oauth2.Config,
	token *oauth2.Token,
	userID string,
) (map[string]any, error) {
	switch kind {
	case proto.CredentialKind_CREDENTIAL_KIND_DISCORD:
		client := cfg.Client(c, token)
		userinfoURL := ac.DiscordUserinfoURL
		if userinfoURL == "" {
			userinfoURL = "https://discord.com/api/users/@me"
		}
		resp, err := client.Get(userinfoURL)
		if err != nil {
			return nil, fmt.Errorf("discord userinfo fetch failed: %w", err)
		}
		defer resp.Body.Close()
		var d models.DiscordUser
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			return nil, fmt.Errorf("discord userinfo parse: %w", err)
		}
		did := strconv.FormatInt(int64(d.DiscordId), 10)
		if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
			UserId:      userID,
			RequesterId: userID,
			Kind:        proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
			Payload:     &proto.LinkCredentialRequest_DiscordId{DiscordId: did},
		}); err != nil {
			return nil, fmt.Errorf("link discord failed: %w", err)
		}
		if avatarURL := auth.DiscordAvatarURL(int64(d.DiscordId), d.Avatar); avatarURL != "" {
			if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
				UserId:      userID,
				RequesterId: userID,
				AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
					AvatarUrlSet: avatarURL,
				},
			}); err != nil {
				// Non-fatal: the credential is linked, but the
				// avatar didn't update. The SPA will see the old
				// avatar until the next refresh.
				log.Printf("link discord: avatar update failed: %v", err)
			}
		}
		return map[string]any{
			"provider": "discord",
			"id":       did,
			"username": d.Username,
			"avatar":   d.Avatar,
		}, nil

	case proto.CredentialKind_CREDENTIAL_KIND_GOOGLE:
		client := cfg.Client(c, token)
		userinfoURL := ac.GoogleUserinfoURL
		if userinfoURL == "" {
			userinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		}
		resp, err := client.Get(userinfoURL)
		if err != nil {
			return nil, fmt.Errorf("google userinfo fetch failed: %w", err)
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
			return nil, fmt.Errorf("google userinfo parse: %w", err)
		}
		if gu.Sub == "" {
			return nil, fmt.Errorf("google userinfo returned empty sub")
		}
		if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
			UserId:      userID,
			RequesterId: userID,
			Kind:        proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
			Payload:     &proto.LinkCredentialRequest_GoogleId{GoogleId: gu.Sub},
		}); err != nil {
			return nil, fmt.Errorf("link google failed: %w", err)
		}
		if avatarURL := auth.GoogleAvatarURL(gu.Picture); avatarURL != "" {
			if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
				UserId:      userID,
				RequesterId: userID,
				AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
					AvatarUrlSet: avatarURL,
				},
			}); err != nil {
				log.Printf("link google: avatar update failed: %v", err)
			}
		}
		return map[string]any{
			"provider": "google",
			"id":       gu.Sub,
			"email":    gu.Email,
			"username": gu.Name,
			"picture":  gu.Picture,
		}, nil
	}
	return nil, fmt.Errorf("unsupported link provider %q", p)
}

// GetLinkComplete godoc
// @Summary      Serve the link-complete HTML page
// @Description  Serves a tiny self-contained HTML page that the popup
// @Description  loads after `/api/auth/link/{provider}/callback`
// @Description  302-redirects into it. The page:
// @Description  1. Decodes the `payload` query parameter (a
// @Description     base64url-encoded JSON object, see the payload
// @Description     schema below).
// @Description  2. Calls `window.opener.postMessage(payload,
// @Description     FRONTEND_URL_ORIGIN)` so the SPA's main window can
// @Description     react (close the popup, refresh linked credentials,
// @Description     show a toast).
// @Description  3. Calls `window.close()`.
// @Description
// @Description  If `window.opener` is missing (popup opened in a new
// @Description  tab, parent navigated away, popup blocker closed the
// parent), the payload is rendered into the visible `<pre>` element so
// the user can copy it manually. The SPA should treat a missing
// postMessage as a fallback trigger and re-run the link via
// @Description  `POST /api/auth/link/{provider}` (literal path).
// @Description
// @Description  Payload schema (JSON object):
// @Description  - `provider` (string): "discord" or "google".
// @Description  - `id` (string): Discord snowflake or Google `sub`.
// @Description  - `username` (string): provider-side display name.
// @Description  - `avatar` (string, Discord only): Discord avatar hash.
// @Description  - `picture` (string, Google only): Google picture URL.
// @Description  - `email` (string, Google only): email from userinfo.
// @Description  - `error` (string): present iff linking errored; the
// @Description    rest of the fields are omitted.
// @Tags         Authentication
// @Produce      html
// @Param        p        path   string  true   "Provider: discord or google"
// @Param        payload  query  string  true   "Base64url-encoded JSON payload produced by /callback"
// @Success      200  "HTML page that postMessages the payload to window.opener"
// @Failure      400  {object}  map[string]string  "Bad Request - payload missing or not valid base64url JSON"
// @Failure      404  {object}  map[string]string  "Not Found - unknown provider"
// @Router       /auth/link/{p}/complete [get]
func (ac *AuthController) GetLinkComplete(c *gin.Context) {
	p := c.Param("p")
	if p != "discord" && p != "google" {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("unknown provider %q", p)})
		return
	}
	if _, ok := decodeLinkPayload(c.Query("payload")); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing or malformed payload"})
		return
	}
	origin := frontendOrigin(config.AppConfig.FrontendURL)
	html := fmt.Sprintf(linkCompleteHTMLTmpl, origin)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_, _ = c.Writer.WriteString(html)
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

// LinkPasswordRequest carries a plaintext password; the server
// hashes it (argon2id) before reaching gRPC.
type LinkPasswordRequest struct {
	Password string `json:"password"`
}

// PostLinkDiscord godoc
// @Summary      Link a Discord account to the authenticated user
// @Description  Attaches a Discord credential to the currently
// @Description  authenticated user via AuthService.LinkCredential.
// @Description  The frontend performs the OAuth code exchange
// @Description  itself, then POSTs the resolved `discord_id`
// @Description  (and optional `avatar_hash`) as query parameters.
// @Description  On success the user's `avatar_url` is refreshed
// @Description  from the Discord CDN when `avatar_hash` is given.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        discord_id   query     string  true   "Discord snowflake id returned from the OAuth userinfo"
// @Param        avatar_hash  query     string  false  "Discord avatar hash; when set, the avatar is refreshed"
// @Success      200  {object}  map[string]string  "linked"
// @Failure      400  {object}  map[string]string  "missing or non-integer discord_id"
// @Failure      401  {object}  map[string]string  "unauthenticated"
// @Router       /auth/link/discord [post]
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

// PostLinkGoogle godoc
// @Summary      Link a Google account to the authenticated user
// @Description  Attaches a Google credential to the currently
// @Description  authenticated user via AuthService.LinkCredential.
// @Description  The frontend performs the OAuth code exchange
// @Description  itself, then POSTs the resolved `google_id`
// @Description  (and optional `picture` URL) as query parameters.
// @Description  On success the user's `avatar_url` is refreshed
// @Description  from the submitted `picture` when present.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        google_id  query     string  true   "Google stable user id from the `sub` claim"
// @Param        picture    query     string  false  "Absolute picture URL from Google userinfo; when set, the avatar is refreshed"
// @Success      200  {object}  map[string]string  "linked"
// @Failure      400  {object}  map[string]string  "missing google_id"
// @Failure      401  {object}  map[string]string  "unauthenticated"
// @Router       /auth/link/google [post]
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

// ChangePasswordRequest is the body of POST /auth/password/change.
// Both passwords are plaintext, hashed server-side. The current
// password is hashed and constant-time-compared against the stored
// hash; the new password replaces the credential on success.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// PostChangePassword godoc
// @Summary      Change the authenticated user's password
// @Description  Hashes the submitted current password and compares it
// @Description  in constant time against the stored hash. On match,
// the old credential is unlinked and the new (hashed) credential is
// @Description  linked. Returns 401 on a wrong current password and
// @Description  400 if the account has no password credential yet
// @Description  (OAuth-only signups should use /auth/link/password first).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      ChangePasswordRequest  true  "current and new password"
// @Success      200      {object}  map[string]string      "password changed"
// @Failure      400      {object}  map[string]string      "missing fields or no password set"
// @Failure      401      {object}  map[string]string      "unauthenticated or wrong current password"
// @Router       /auth/password/change [post]
func (ac *AuthController) PostChangePassword(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil ||
		req.CurrentPassword == "" || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
		return
	}
	if req.CurrentPassword == req.NewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new_password must differ from current_password"})
		return
	}

	lookup, err := ac.authService.FindCredentialByProvider(c, &proto.FindCredentialByProviderRequest{
		Kind:       proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Identifier: &proto.FindCredentialByProviderRequest_Email{Email: user.Email},
	})
	if err != nil {
		if auth.IsNotFound(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no password is set on this account; use /auth/link/password first"})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("lookup password credential: %w", err))
		return
	}
	storedHash := lookup.GetCredential().GetPasswordHash()
	credentialID := lookup.GetCredential().GetId()
	if storedHash == "" || credentialID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no password credential to update"})
		return
	}

	ok, verr := auth.Argon2Hasher{}.Verify(req.CurrentPassword, storedHash)
	if verr != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid current password"})
		return
	}

	newHash, err := auth.Argon2Hasher{}.Hash(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Unlink the old row first. LinkCredential returns ALREADY_EXISTS
	// when a PASSWORD credential already exists, so we can't just overwrite.
	if _, err := ac.authService.UnlinkCredential(c, &proto.UnlinkCredentialRequest{
		CredentialId: credentialID,
		UserId:       user.ID,
		RequesterId:  user.ID,
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("unlink old password credential: %w", err))
		return
	}

	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload:     &proto.LinkCredentialRequest_PasswordHash{PasswordHash: newHash},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link new password credential: %w", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"changed": "password"})
}

// PostLinkPassword godoc
// @Summary      Link a password to the authenticated user
// @Description  Sets a password credential on the currently
// @Description  authenticated user. The body carries the new
// @Description  plaintext password; the server hashes it (argon2id)
// @Description  before reaching gRPC. OAuth-only signups should use
// @Description  this endpoint to add a password fallback.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      LinkPasswordRequest  true  "new plaintext password"
// @Success      200  {object}  map[string]string  "linked"
// @Failure      400  {object}  map[string]string  "missing or invalid password"
// @Failure      401  {object}  map[string]string  "unauthenticated"
// @Router       /auth/link/password [post]
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
	hash, err := auth.Argon2Hasher{}.Hash(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload:     &proto.LinkCredentialRequest_PasswordHash{PasswordHash: hash},
	}); err != nil {
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

// GetPasskeysForMe godoc
// @Summary      List my passkeys
// @Description  Returns the passkeys owned by the currently authenticated
// @Description  user. Revoked rows are excluded unless `include_revoked=true`.
// @Tags         Authentication
// @Produce      json
// @Param        include_revoked  query     bool  false  "Include revoked passkeys"
// @Success      200              {object}  map[string]interface{}  "passkeys array"
// @Failure      401              {object}  map[string]string      "Unauthorized - no session"
// @Router       /auth/passkey/list [get]
func (ac *AuthController) GetPasskeysForMe(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	includeRevoked := strings.EqualFold(c.Query("include_revoked"), "true")
	resp, err := ac.authService.ListPasskeys(c.Request.Context(), &proto.ListPasskeysRequest{
		UserId:         user.ID,
		IncludeRevoked: includeRevoked,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("list passkeys failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"passkeys": resp.GetPasskeys()})
}

// DeletePasskey godoc
// @Summary      Revoke one of my passkeys
// @Description  Revokes the passkey identified by `:id`. The actor must
// @Description  own it -- cross-user revoke attempts are rejected as 404
// @Description  so we do not leak existence of passkeys owned by other
// @Description  users.
// @Tags         Authentication
// @Param        id  path  string  true  "Passkey ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string  "Bad Request - missing id"
// @Failure      401  {object}  map[string]string  "Unauthorized - no session"
// @Failure      404  {object}  map[string]string  "Not Found - passkey not owned by caller"
// @Router       /auth/passkey/{id} [delete]
func (ac *AuthController) DeletePasskey(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	passkeyID := strings.TrimSpace(c.Param("id"))
	if passkeyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passkey id is required"})
		return
	}
	if _, err := ac.authService.RevokePasskey(c.Request.Context(), &proto.RevokePasskeyRequest{
		PasskeyId:   passkeyID,
		UserId:      user.ID,
		RequesterId: user.ID,
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("revoke passkey failed: %w", err))
		return
	}
	c.Status(http.StatusNoContent)
}
