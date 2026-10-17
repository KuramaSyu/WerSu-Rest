package auth

import (
	"fmt"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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

// Logout clears the user session.
func (ac *AuthController) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
