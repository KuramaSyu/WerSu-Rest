package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

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
