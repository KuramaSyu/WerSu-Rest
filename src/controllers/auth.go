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
)

// AuthController handles authentication logic
type AuthController struct {
	OAuthConfig *oauth2.Config
	userService *proto.UserServiceClient
}

// NewAuthController creates a new auth controller
func NewAuthController(oauthConfig *oauth2.Config, userService *proto.UserServiceClient) *AuthController {
	return &AuthController{
		OAuthConfig: oauthConfig,
		userService: userService,
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

	var d_user models.JsUser
	if err := json.NewDecoder(resp.Body).Decode(&d_user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user info"})
		return
	}
	user, err := d_user.Parse()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID was not parsable to int"})
	}

	session.Set("user", *user)
	discordId := int64(user.DiscordId)
	grpcUser, err := (*ac.userService).GetUser(c, &proto.GetUserRequest{
		DiscordId: &discordId,
	})

	if err != nil {
		println("%v", err.Error())
		// failed to get user -> post user
		grpcUser, err = (*ac.userService).PostUser(c, &proto.PostUserRequest{
			DiscordId:     int64(user.DiscordId),
			Avatar:        user.Avatar,
			Username:      user.Username,
			Discriminator: user.Discriminator,
			Email:         user.Email,
		})
		if err != nil {
			// failed to post user -> error
			log.Printf("user: %v; Error: %v", user, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to post user to gRPC service"})
			return
		}
	}

	log.Printf("User %v logged in via Discord OAuth, gRPC ID: %v", user.Username, grpcUser.Id)
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
	session := sessions.Default(c)
	user := session.Get("user")
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}
	println("%v", user)
	user_go_old := user.(models.User)
	// fetch again
	discord_id := int64(user_go_old.DiscordId)
	user_go, err := (*ac.userService).GetUser(c, &proto.GetUserRequest{DiscordId: &discord_id})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user from gRPC service"})
		return
	}
	c.JSON(http.StatusOK, user_go.ParseJS())
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
