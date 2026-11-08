package controllers

import (
	"fmt"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserController exposes user-discovery endpoints backed by the UserService
// gRPC API. The existing CRUD routes stay on AuthController because they are
// wrappers around the auth service.
type UserController struct {
	UserService *proto.UserServiceClient
}

// NewUserController creates a controller for user-discovery routes.
func NewUserController(userService *proto.UserServiceClient) *UserController {
	return &UserController{UserService: userService}
}

// SearchUsersQuery is the query string for GET /api/users/search.
type SearchUsersQuery struct {
	Query string `form:"query" example:"ku"`
}

// GetUsersByIdsBody is the JSON body for POST /api/users/by-ids.
type GetUsersByIdsBody struct {
	Ids []string `json:"ids" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
}

// UserSummary is the public user shape returned by the discovery routes.
// It deliberately omits the user's email address.
type UserSummary struct {
	Id            string `json:"id"`
	DiscordId     string `json:"discord_id,omitempty"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator,omitempty"`
	Avatar        string `json:"avatar,omitempty"`
}

func userSummaryFromProto(user *proto.User) UserSummary {
	return UserSummary{
		Id:            user.GetId(),
		DiscordId:     fmt.Sprintf("%d", user.GetDiscordId()),
		Username:      user.GetUsername(),
		Discriminator: user.GetDiscriminator(),
		Avatar:        user.GetAvatar(),
	}
}

func userSummariesFromProto(users []*proto.User) []UserSummary {
	replies := make([]UserSummary, 0, len(users))
	for _, user := range users {
		replies = append(replies, userSummaryFromProto(user))
	}
	return replies
}

// setUserGRPCError maps a failed UserService call to an HTTP response.
func setUserGRPCError(c *gin.Context, err error, op string) {
	switch status.Code(err) {
	case codes.InvalidArgument:
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("%s: %w", op, err))
	case codes.NotFound:
		utils.SetGinError(c, http.StatusNotFound, fmt.Errorf("%s: %w", op, err))
	case codes.PermissionDenied:
		utils.SetGinError(c, http.StatusForbidden, fmt.Errorf("%s: %w", op, err))
	case codes.Unauthenticated:
		utils.SetGinError(c, http.StatusUnauthorized, fmt.Errorf("%s: %w", op, err))
	default:
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
	}
}

// SearchUsers godoc
// @Summary      Search users
// @Description  Searches users by username/id fragment or exact email. The
// @Description  gRPC backend returns at most ten hits. Email addresses are
// @Description  omitted from the REST response.
// @Tags         users
// @Produce      json
// @Security     CookieAuth
// @Param        query  query     string  true  "Search query"
// @Success      200    {array}   UserSummary
// @Failure      400    {object}  map[string]string "Bad Request - invalid query"
// @Failure      401    {object}  map[string]string "Unauthorized - no session or JWT"
// @Failure      403    {object}  map[string]string "Forbidden"
// @Failure      500    {object}  map[string]string "Internal Server Error - gRPC service failure"
// @Router       /api/users/search [get]
func (uc *UserController) SearchUsers(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query SearchUsersQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	resp, err := (*uc.UserService).SearchUser(c, &proto.SearchUserRequest{
		Query:  query.Query,
		UserId: user.ID,
	})
	if err != nil {
		setUserGRPCError(c, err, "search users")
		return
	}

	c.JSON(http.StatusOK, userSummariesFromProto(resp.GetUsers()))
}

// GetUsersByIds godoc
// @Summary      Fetch users by ids
// @Description  Resolves many user ids in one request. Unknown ids are
// @Description  omitted. Email addresses are omitted from the REST response.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      GetUsersByIdsBody  true  "User ids"
// @Success      200      {array}   UserSummary
// @Failure      400      {object}  map[string]string "Bad Request - invalid body"
// @Failure      401      {object}  map[string]string "Unauthorized - no session or JWT"
// @Failure      403      {object}  map[string]string "Forbidden"
// @Failure      500      {object}  map[string]string "Internal Server Error - gRPC service failure"
// @Router       /api/users/by-ids [post]
func (uc *UserController) GetUsersByIds(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body GetUsersByIdsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*uc.UserService).GetUsers(c, &proto.GetUsersRequest{
		UserId: user.ID,
		Ids:    body.Ids,
	})
	if err != nil {
		setUserGRPCError(c, err, "fetch users by ids")
		return
	}

	c.JSON(http.StatusOK, userSummariesFromProto(resp.GetUsers()))
}
