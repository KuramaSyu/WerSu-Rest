package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// UserController handles user routes
type UserController struct {
	// userClient pb.UserServiceClient (example)
}

func NewUserController() *UserController {
	return &UserController{}
}

// GetUser godoc
// @Summary Get user by ID
// @Description Fetch user via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /users/{id} [get]
func (uc *UserController) GetUser(c *gin.Context) {
	id := c.Param("id")

	// Example: call gRPC service here
	// resp, err := uc.userClient.GetUser(ctx, &pb.GetUserRequest{Id: id})

	c.JSON(http.StatusOK, gin.H{
		"id":   id,
		"name": "Mock User",
	})
}
