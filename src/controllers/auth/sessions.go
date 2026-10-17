package auth

import (
	"log"
	"net/http"

	ctrl "github.com/KuramaSyu/WerSu-Rest/src/controllers"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
)

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

// GetPublicAccessToken godoc
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

	token, err := utils.GenerateJWT(userId, ac.JWTSecret, ctrl.UnwrapNullableDatetime(resp.OnlineUntil))
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	c.JSON(http.StatusOK, GetAccessTokenReply{
		Token: token,
	})
}
