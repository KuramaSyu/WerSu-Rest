package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Login initiates Discord OAuth flow.
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

// Callback handles OAuth callback from Discord.
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
