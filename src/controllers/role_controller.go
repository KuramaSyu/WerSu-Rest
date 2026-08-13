package controllers

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RoleController handles REST routes for RBAC roles.
//
// Roles group users together so notes / directories can grant access
// to the role as a whole.  Metadata (name, description) lives in
// Postgres; membership edges (`user#member_of@role`) live in
// SpiceDB.  Every write path is gated on `manage` permission on
// the role; `create_role` falls back to the super-admin env-var
// list on the gRPC side.
type RoleController struct {
	RoleService *proto.RoleServiceClient
}

// NewRoleController creates a controller for role-related routes.
func NewRoleController(roleService *proto.RoleServiceClient) *RoleController {
	return &RoleController{RoleService: roleService}
}

// setRoleGRPCError writes a REST error response for a failed gRPC call.
// PermissionDenied -> 403, NotFound -> 404, everything else -> 500.
func setRoleGRPCError(c *gin.Context, err error, op string) {
	if grpcErr, ok := status.FromError(err); ok {
		switch grpcErr.Code() {
		case codes.PermissionDenied:
			SetGinError(c, http.StatusForbidden, fmt.Errorf("%s: %w", op, err))
			return
		case codes.NotFound:
			SetGinError(c, http.StatusNotFound, fmt.Errorf("%s: %w", op, err))
			return
		}
	}
	SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}

// RoleReply is the REST representation of a role returned to clients.
type RoleReply struct {
	Id          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// UserRoleMembershipReply is the REST representation of a single
// `user#member_of@role` edge.
type UserRoleMembershipReply struct {
	UserId    string     `json:"user_id"`
	RoleId    string     `json:"role_id"`
	GrantedAt *time.Time `json:"granted_at,omitempty"`
}

// CreateRoleBody is the JSON body for creating a role.
//
// `description` is optional; absent or empty string both clear the description.
type CreateRoleBody struct {
	Name        string `json:"name" binding:"required" example:"engineering"`
	Description string `json:"description,omitempty" example:"All engineers"`
}

// UpdateRoleBody is the JSON body for updating a role.
//
// Only `name` is optional and skipped when absent. `description` is
// always forwarded (empty string clears the description).
type UpdateRoleBody struct {
	Id          string  `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	Name        *string `json:"name,omitempty" example:"engineering"`
	Description string  `json:"description,omitempty" example:"All engineers"`
}

// DeleteRoleBody is the JSON body for deleting a role.
type DeleteRoleBody struct {
	Id string `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
}

// AddUserToRoleBody is the JSON body for adding a user to a role's membership.
type AddUserToRoleBody struct {
	RoleId        string `json:"role_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	SubjectUserId string `json:"subject_user_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// RemoveUserFromRoleBody is the JSON body for removing a user from a role's membership.
type RemoveUserFromRoleBody struct {
	RoleId        string `json:"role_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	SubjectUserId string `json:"subject_user_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// GetRolesQuery contains the optional query parameters used to filter roles.
//
// Nil means the client did not supply that filter.  Omitted and
// explicitly null are both treated the same way: not supplied.
type GetRolesQuery struct {
	Name     *string `form:"name" example:"engineering"`
	MemberId *string `form:"member_id" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// GetRolesForUserQuery contains the subject user id whose roles we want to list.
type GetRolesForUserQuery struct {
	SubjectUserId string `form:"subject_user_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// GetUsersForRoleQuery contains the role id whose members we want to list.
type GetUsersForRoleQuery struct {
	RoleId string `form:"role_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
}

// roleReplyFromProto converts a gRPC Role into the REST response type.
func roleReplyFromProto(role *proto.Role) RoleReply {
	var createdAt *time.Time
	if role.GetCreatedAt() != nil {
		t := role.GetCreatedAt().AsTime()
		createdAt = &t
	}
	return RoleReply{
		Id:          role.GetId(),
		Name:        role.GetName(),
		Description: role.GetDescription(),
		CreatedAt:   createdAt,
	}
}

// userRoleMembershipReplyFromProto converts a gRPC UserRoleMembership
// into the REST response type.
func userRoleMembershipReplyFromProto(m *proto.UserRoleMembership) UserRoleMembershipReply {
	var grantedAt *time.Time
	if m.GetGrantedAt() != nil {
		t := m.GetGrantedAt().AsTime()
		grantedAt = &t
	}
	return UserRoleMembershipReply{
		UserId:    m.GetUserId(),
		RoleId:    m.GetRoleId(),
		GrantedAt: grantedAt,
	}
}

// roleFilterFromQuery converts REST query parameters into a protobuf role filter.
func roleFilterFromQuery(query GetRolesQuery) *proto.RoleFilter {
	return &proto.RoleFilter{
		Name:     query.Name,
		MemberId: query.MemberId,
	}
}

// CreateRole godoc
// @Summary Create role
// @Description Creates a role via gRPC service.  Caller must be in the
// @Description super-admin env-var list on the gRPC backend.
// @Tags roles
// @Accept json
// @Produce json
// @Param payload body CreateRoleBody true "Create role request"
// @Success 200 {object} RoleReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles [post]
func (rc *RoleController) CreateRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	created, err := (*rc.RoleService).CreateRole(c, &proto.CreateRoleRequest{
		UserId:      user.ID,
		Name:        body.Name,
		Description: body.Description,
	})
	if err != nil {
		setRoleGRPCError(c, err, "create role")
		return
	}

	c.JSON(http.StatusOK, roleReplyFromProto(created))
}

// GetRole godoc
// @Summary Get role by ID
// @Description Fetch a single role by ID via gRPC service
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} RoleReply
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/{id} [get]
func (rc *RoleController) GetRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Param("id")
	if id == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing role ID"))
		return
	}

	role, err := (*rc.RoleService).GetRole(c, &proto.GetRoleRequest{
		UserId: user.ID,
		Id:     id,
	})
	if err != nil {
		setRoleGRPCError(c, err, "fetch role")
		return
	}

	c.JSON(http.StatusOK, roleReplyFromProto(role))
}

// GetRoles godoc
// @Summary List roles
// @Description Fetch roles matching an optional filter via gRPC service
// @Tags roles
// @Accept json
// @Produce json
// @Param name query string false "Filter by exact role name"
// @Param member_id query string false "Filter to roles this user is a member of"
// @Success 200 {object} []RoleReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles [get]
func (rc *RoleController) GetRoles(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetRolesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	stream, err := (*rc.RoleService).GetRoles(c, &proto.GetRolesRequest{
		UserId: user.ID,
		Filter: roleFilterFromQuery(query),
	})
	if err != nil {
		setRoleGRPCError(c, err, "fetch roles")
		return
	}

	roles := make([]RoleReply, 0)
	for {
		role, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream roles via gRPC service: %w", err))
			return
		}
		roles = append(roles, roleReplyFromProto(role))
	}

	c.JSON(http.StatusOK, roles)
}

// UpdateRole godoc
// @Summary Update role
// @Description Updates a role's metadata via gRPC service.  Caller must
// @Description hold `manage` on the role.
// @Tags roles
// @Accept json
// @Produce json
// @Param payload body UpdateRoleBody true "Update role request"
// @Success 200 {object} RoleReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles [patch]
func (rc *RoleController) UpdateRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body UpdateRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	updated, err := (*rc.RoleService).UpdateRole(c, &proto.UpdateRoleRequest{
		UserId:      user.ID,
		Id:          body.Id,
		Name:        body.Name,
		Description: body.Description,
	})
	if err != nil {
		setRoleGRPCError(c, err, "update role")
		return
	}

	c.JSON(http.StatusOK, roleReplyFromProto(updated))
}

// DeleteRole godoc
// @Summary Delete role
// @Description Deletes a role via gRPC service.  Caller must hold
// @Description `manage` on the role.  Membership edges become dangling
// @Description references in SpiceDB (they silently evaluate to nothing);
// @Description cleanup of those is the caller's responsibility.
// @Tags roles
// @Accept json
// @Produce json
// @Param payload body DeleteRoleBody true "Delete role request"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles [delete]
func (rc *RoleController) DeleteRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DeleteRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	_, err = (*rc.RoleService).DeleteRole(c, &proto.DeleteRoleRequest{
		UserId: user.ID,
		Id:     body.Id,
	})
	if err != nil {
		setRoleGRPCError(c, err, "delete role")
		return
	}

	c.Status(http.StatusNoContent)
}

// AddUserToRole godoc
// @Summary Add user to role
// @Description Adds a user as a member of a role.  Caller must hold
// @Description `manage` on the role.
// @Tags roles
// @Accept json
// @Produce json
// @Param payload body AddUserToRoleBody true "Add user to role request"
// @Success 200 {object} UserRoleMembershipReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/members [post]
func (rc *RoleController) AddUserToRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body AddUserToRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	membership, err := (*rc.RoleService).AddUserToRole(c, &proto.AddUserToRoleRequest{
		UserId:        user.ID,
		RoleId:        body.RoleId,
		SubjectUserId: body.SubjectUserId,
	})
	if err != nil {
		setRoleGRPCError(c, err, "add user to role")
		return
	}

	c.JSON(http.StatusOK, userRoleMembershipReplyFromProto(membership))
}

// RemoveUserFromRole godoc
// @Summary Remove user from role
// @Description Removes a user from a role's membership.  Caller must
// @Description hold `manage` on the role.
// @Tags roles
// @Accept json
// @Produce json
// @Param payload body RemoveUserFromRoleBody true "Remove user from role request"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/members [delete]
func (rc *RoleController) RemoveUserFromRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body RemoveUserFromRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	_, err = (*rc.RoleService).RemoveUserFromRole(c, &proto.RemoveUserFromRoleRequest{
		UserId:        user.ID,
		RoleId:        body.RoleId,
		SubjectUserId: body.SubjectUserId,
	})
	if err != nil {
		setRoleGRPCError(c, err, "remove user from role")
		return
	}

	c.Status(http.StatusNoContent)
}

// GetRolesForUser godoc
// @Summary List roles for a user
// @Description Lists every role the given user is a member of.
// @Tags roles
// @Accept json
// @Produce json
// @Param subject_user_id query string true "Subject user ID"
// @Success 200 {object} []RoleReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/by-user [get]
func (rc *RoleController) GetRolesForUser(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetRolesForUserQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	stream, err := (*rc.RoleService).GetRolesForUser(c, &proto.GetRolesForUserRequest{
		UserId:        user.ID,
		SubjectUserId: query.SubjectUserId,
	})
	if err != nil {
		setRoleGRPCError(c, err, "fetch roles for user")
		return
	}

	roles := make([]RoleReply, 0)
	for {
		role, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream roles via gRPC service: %w", err))
			return
		}
		roles = append(roles, roleReplyFromProto(role))
	}

	c.JSON(http.StatusOK, roles)
}

// GetUsersForRole godoc
// @Summary List users for a role
// @Description Lists every user that is a member of the given role.
// @Tags roles
// @Accept json
// @Produce json
// @Param role_id query string true "Role ID"
// @Success 200 {object} []UserRoleMembershipReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/members [get]
func (rc *RoleController) GetUsersForRole(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetUsersForRoleQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	stream, err := (*rc.RoleService).GetUsersForRole(c, &proto.GetUsersForRoleRequest{
		UserId: user.ID,
		RoleId: query.RoleId,
	})
	if err != nil {
		setRoleGRPCError(c, err, "fetch users for role")
		return
	}

	memberships := make([]UserRoleMembershipReply, 0)
	for {
		m, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream memberships via gRPC service: %w", err))
			return
		}
		memberships = append(memberships, userRoleMembershipReplyFromProto(m))
	}

	c.JSON(http.StatusOK, memberships)
}
