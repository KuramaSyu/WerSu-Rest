package controllers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

type PermissionController struct {
	PermissionService *proto.PermissionServiceClient
}

func NewPermissionController(permissionService *proto.PermissionServiceClient) *PermissionController {
	return &PermissionController{PermissionService: permissionService}
}

const (
	PermissionObjectTypeNote      = "note"
	PermissionObjectTypeDirectory = "directory"
	PermissionObjectTypeUser      = "user"

	PermissionRelationOwner           = "owner"
	PermissionRelationAdmin           = "admin"
	PermissionRelationWriter          = "writer"
	PermissionRelationReader          = "reader"
	PermissionRelationParent          = "parent"
	PermissionRelationParentDirectory = "parent_directory"
)

// GetPermissionsQuery defines query parameters for fetching permissions.
type GetPermissionsQuery struct {
	ObjectType string `form:"object_type" binding:"required,oneof=note directory" enums:"note,directory" example:"note"`
	ObjectId   string `form:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PermissionSubjectRequest defines the subject side of a relationship.
type PermissionSubjectRequest struct {
	ObjectType string `json:"object_type" binding:"required,oneof=user directory" enums:"user,directory" example:"user"`
	ObjectId   string `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PermissionResourceRequest defines an optional explicit resource for a relationship.
type PermissionResourceRequest struct {
	ObjectType string `json:"object_type" binding:"required,oneof=note directory" enums:"note,directory" example:"note"`
	ObjectId   string `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PermissionRelationshipRequest defines one relationship tuple.
type PermissionRelationshipRequest struct {
	Relation string                     `json:"relation" binding:"required,oneof=owner admin writer reader parent parent_directory" enums:"owner,admin,writer,reader,parent,parent_directory" example:"reader"`
	Subject  *PermissionSubjectRequest  `json:"subject,omitempty"`
	Resource *PermissionResourceRequest `json:"resource,omitempty"`
}

// CreatePermissionBody defines request body for creating a single permission relationship.
type CreatePermissionBody struct {
	ObjectType   string                        `json:"object_type" binding:"required,oneof=note directory" enums:"note,directory" example:"note"`
	ObjectId     string                        `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Relationship PermissionRelationshipRequest `json:"relationship" binding:"required"`
}

// DeletePermissionBody defines request body for deleting a single permission relationship.
type DeletePermissionBody struct {
	ObjectType   string                        `json:"object_type" binding:"required,oneof=note directory" enums:"note,directory" example:"note"`
	ObjectId     string                        `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Relationship PermissionRelationshipRequest `json:"relationship" binding:"required"`
}

// ReplacePermissionsBody defines request body for replacing all permission relationships.
type ReplacePermissionsBody struct {
	ObjectType    string                          `json:"object_type" binding:"required,oneof=note directory" enums:"note,directory" example:"note"`
	ObjectId      string                          `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Relationships []PermissionRelationshipRequest `json:"relationships" binding:"required"`
}

// PermissionsReply is the REST response containing the full permission set for an object.
type PermissionsReply struct {
	ObjectType    string                        `json:"object_type" enums:"PERMISSION_OBJECT_TYPE_UNSPECIFIED,PERMISSION_OBJECT_TYPE_NOTE,PERMISSION_OBJECT_TYPE_DIRECTORY"`
	ObjectId      string                        `json:"object_id"`
	Relationships []PermissionRelationshipReply `json:"relationships"`
}

// parsePermissionObjectType normalizes a REST `object_type` value and maps it
// to the protobuf enum expected by PermissionService.
//
// Accepted values:
//   - "note" / "PERMISSION_OBJECT_TYPE_NOTE"
//   - "directory" / "PERMISSION_OBJECT_TYPE_DIRECTORY"
//   - "user" / "PERMISSION_OBJECT_TYPE_USER"
//   - "unspecified" / "PERMISSION_OBJECT_TYPE_UNSPECIFIED"
//
// Used by:
//   - `GetPermissions()`
//   - `CreatePermission()`
//   - `DeletePermission()`
//   - `ReplacePermissions()`
//   - `permissionRelationshipRequestToProto()` when mapping `resource.object_type`
func parsePermissionObjectType(objectType string) (proto.PermissionObjectType, error) {
	normalized := strings.ToUpper(strings.TrimSpace(objectType))
	switch normalized {
	case "NOTE", "PERMISSION_OBJECT_TYPE_NOTE":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_NOTE, nil
	case "DIRECTORY", "PERMISSION_OBJECT_TYPE_DIRECTORY":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_DIRECTORY, nil
	case "USER", "PERMISSION_OBJECT_TYPE_USER":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_USER, nil
	case "UNSPECIFIED", "PERMISSION_OBJECT_TYPE_UNSPECIFIED":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_UNSPECIFIED, nil
	default:
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_UNSPECIFIED, fmt.Errorf("invalid object_type: %s", objectType)
	}
}

// parsePermissionRelation validates and normalizes the relationship name from
// REST input to the canonical lowercase value used by the permission backend.
//
// Used by:
//   - `permissionRelationshipRequestToProto()`
func parsePermissionRelation(relation string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(relation))
	switch normalized {
	case PermissionRelationOwner,
		PermissionRelationAdmin,
		PermissionRelationWriter,
		PermissionRelationReader,
		PermissionRelationParent,
		PermissionRelationParentDirectory:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid relation: %s", relation)
	}
}

// permissionRelationshipRequestToProto maps a REST relationship payload into a
// protobuf `PermissionRelationship`.
//
// This helper also validates:
//   - `relation` via `parsePermissionRelation()`
//   - `resource.object_type` via `parsePermissionObjectType()`
//
// Used by:
//   - `CreatePermission()`
//   - `DeletePermission()`
//   - `ReplacePermissions()`
func permissionRelationshipRequestToProto(relationship PermissionRelationshipRequest) (*proto.PermissionRelationship, error) {
	relation, err := parsePermissionRelation(relationship.Relation)
	if err != nil {
		return nil, err
	}

	grpcRelationship := &proto.PermissionRelationship{
		Relation: relation,
	}

	if relationship.Subject != nil {
		subjectType, err := parsePermissionObjectType(relationship.Subject.ObjectType)
		if err != nil {
			return nil, err
		}

		grpcRelationship.Subject = &proto.PermissionSubject{
			ObjectType: subjectType,
			ObjectId:   relationship.Subject.ObjectId,
		}
	}

	if relationship.Resource != nil {
		resourceType, err := parsePermissionObjectType(relationship.Resource.ObjectType)
		if err != nil {
			return nil, err
		}

		grpcRelationship.Resource = &proto.PermissionResource{
			ObjectType: resourceType,
			ObjectId:   relationship.Resource.ObjectId,
		}
	}

	return grpcRelationship, nil
}

// permissionsReplyFromProto converts the gRPC `PermissionsResponse` into the
// REST `PermissionsReply` shape.
//
// Used by:
//   - `GetPermissions()`
//   - `CreatePermission()`
//   - `DeletePermission()`
//   - `ReplacePermissions()`
func permissionsReplyFromProto(response *proto.PermissionsResponse) PermissionsReply {
	relationships := make([]PermissionRelationshipReply, 0, len(response.GetRelationships()))
	for _, relationship := range response.GetRelationships() {
		relationships = append(relationships, PermissionRelationshipReplyFromProto(relationship))
	}

	return PermissionsReply{
		ObjectType:    response.GetObjectType().String(),
		ObjectId:      response.GetObjectId(),
		Relationships: relationships,
	}
}

// GetPermissions godoc
// @Summary Get permissions for an object
// @Description Fetch permissions via gRPC PermissionService
// @Tags permissions
// @Accept json
// @Produce json
// @Param object_type query string true "Object type" Enums(note, directory)
// @Param object_id query string true "Object ID"
// @Success 200 {object} PermissionsReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [get]
func (pc *PermissionController) GetPermissions(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetPermissionsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	objectType, err := parsePermissionObjectType(query.ObjectType)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	response, err := (*pc.PermissionService).GetPermissions(c, &proto.GetPermissionsRequest{
		ObjectType: objectType,
		ObjectId:   query.ObjectId,
		UserId:     user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to get permissions via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, permissionsReplyFromProto(response))
}

// CreatePermission godoc
// @Summary Create a permission relationship
// @Description Create permission via gRPC PermissionService
// @Tags permissions
// @Accept json
// @Produce json
// @Param payload body CreatePermissionBody true "Create permission request"
// @Success 200 {object} PermissionsReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [post]
func (pc *PermissionController) CreatePermission(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreatePermissionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	objectType, err := parsePermissionObjectType(body.ObjectType)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	relationship, err := permissionRelationshipRequestToProto(body.Relationship)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	response, err := (*pc.PermissionService).CreatePermission(c, &proto.CreatePermissionRequest{
		ObjectType:   objectType,
		ObjectId:     body.ObjectId,
		Relationship: relationship,
		UserId:       user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to create permission via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, permissionsReplyFromProto(response))
}

// DeletePermission godoc
// @Summary Delete a permission relationship
// @Description Delete permission via gRPC PermissionService
// @Tags permissions
// @Accept json
// @Produce json
// @Param payload body DeletePermissionBody true "Delete permission request"
// @Success 200 {object} PermissionsReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [delete]
func (pc *PermissionController) DeletePermission(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DeletePermissionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	objectType, err := parsePermissionObjectType(body.ObjectType)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	relationship, err := permissionRelationshipRequestToProto(body.Relationship)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	response, err := (*pc.PermissionService).DeletePermission(c, &proto.DeletePermissionRequest{
		ObjectType:   objectType,
		ObjectId:     body.ObjectId,
		Relationship: relationship,
		UserId:       user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to delete permission via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, permissionsReplyFromProto(response))
}

// ReplacePermissions godoc
// @Summary Replace all permissions for an object
// @Description Replace permissions via gRPC PermissionService
// @Tags permissions
// @Accept json
// @Produce json
// @Param payload body ReplacePermissionsBody true "Replace permissions request"
// @Success 200 {object} PermissionsReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [put]
func (pc *PermissionController) ReplacePermissions(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body ReplacePermissionsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	objectType, err := parsePermissionObjectType(body.ObjectType)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	relationships := make([]*proto.PermissionRelationship, 0, len(body.Relationships))
	for _, relationshipBody := range body.Relationships {
		relationship, err := permissionRelationshipRequestToProto(relationshipBody)
		if err != nil {
			SetGinError(c, http.StatusBadRequest, err)
			return
		}
		relationships = append(relationships, relationship)
	}

	response, err := (*pc.PermissionService).ReplacePermissions(c, &proto.ReplacePermissionsRequest{
		ObjectType:    objectType,
		ObjectId:      body.ObjectId,
		Relationships: relationships,
		UserId:        user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to replace permissions via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, permissionsReplyFromProto(response))
}
