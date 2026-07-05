package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

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

// AuthController handles authentication logic
type AuthController struct {
	OAuthConfig  *oauth2.Config
	userService  *proto.UserServiceClient
	shareService *proto.SharingServiceClient
	JWTSecret    string
}

// NewAuthController creates a new auth controller
func NewAuthController(oauthConfig *oauth2.Config, userService *proto.UserServiceClient, shareService *proto.SharingServiceClient, jwtSecret string) *AuthController {
	return &AuthController{
		OAuthConfig:  oauthConfig,
		userService:  userService,
		shareService: shareService,
		JWTSecret:    jwtSecret,
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token"})
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

	//session.Set("d_user", *user)
	discordId := int64(d_user.DiscordId)
	grpcUser, err := (*ac.userService).GetUser(c, &proto.GetUserRequest{
		DiscordId: &discordId,
	})

	if err != nil {
		grpcErr, ok := status.FromError(err)
		if !ok || grpcErr.Code() != codes.NotFound {
			log.Printf("Failed to get user from gRPC service: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "gRPC service is unavailable"})
			return
		}

		// failed to get user -> post user
		grpcUser, err = (*ac.userService).PostUser(c, &proto.PostUserRequest{
			DiscordId:     int64(d_user.DiscordId),
			Avatar:        d_user.Avatar,
			Username:      d_user.Username,
			Discriminator: d_user.Discriminator,
			Email:         d_user.Email,
		})
		if err != nil {
			// failed to post user -> error
			log.Printf("user: %v; Error: %v", d_user, err)
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to post user to gRPC service: %w", err))
			return
		}
	}
	user := models.User{
		ID:            grpcUser.Id,
		DiscordId:     models.Snowflake(grpcUser.DiscordId),
		Username:      grpcUser.Username,
		Discriminator: grpcUser.Discriminator,
		Avatar:        grpcUser.Avatar,
		Email:         grpcUser.Email,
	}
	session.Set("user", user)

	log.Printf("User %v logged in via Discord OAuth, gRPC ID: %v", grpcUser.Username, grpcUser.Id)
	if err := session.Save(); err != nil {
		log.Printf("user: %v; Error: %v", grpcUser, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	redirect_url := fmt.Sprintf("%v", config.AppConfig.FrontendURL)
	c.Redirect(http.StatusTemporaryRedirect, redirect_url)
}

// GetUser returns the current authenticated user
func (ac *AuthController) GetUser(c *gin.Context) {
	user, _, err := UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	// fetch again
	discord_id := int64(user.DiscordId)
	user_backend, err := (*ac.userService).GetUser(c, &proto.GetUserRequest{DiscordId: &discord_id})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch user via gRPC service: %w", err))
		return
	}
	c.JSON(http.StatusOK, user_backend.ParseJS())
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
