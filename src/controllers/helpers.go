package controllers

import (
	"fmt"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// UserFromSession retrieves the authenticated user from the current session.
// It returns the user model, an HTTP status code, and an error if the user is not authenticated
// or if the session data is malformed.
//
// Returns:
//   - *models.User: The authenticated user if successful
//   - int: HTTP status code (200 for success, 401 for unauthorized, 500 for internal error)
//   - error: Error message if retrieval fails
func UserFromSession(c *gin.Context) (*models.User, int, error) {
	session := sessions.Default(c)
	userData := session.Get("user")
	if userData == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("not logged in")
	}

	user_go, ok := userData.(models.User)
	if !ok {
		return nil, http.StatusInternalServerError, fmt.Errorf("wrong user format: %v %v", userData, ok)
	}

	return &user_go, http.StatusOK, nil
}

// SetGinError is a helper function that sends a JSON error response.
// It formats the error message and sets the appropriate HTTP status code.
//
// Parameters:
//   - c: The Gin context
//   - status: HTTP status code to return
//   - err: The error to send in the response body
func SetGinError(c *gin.Context, status int, err error) {
	c.JSON(status, gin.H{"error": err.Error()})

}
