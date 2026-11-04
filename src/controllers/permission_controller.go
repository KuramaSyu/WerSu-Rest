package controllers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PermissionController struct {
	PermissionService *proto.PermissionServiceClient
}

func NewPermissionController(permissionService *proto.PermissionServiceClient) *PermissionController {
	return &PermissionController{PermissionService: permissionService}
}

const (
	PermissionObjectTypeNote       = "note"
	PermissionObjectTypeDirectory  = "directory"
	PermissionObjectTypeUser       = "user"
	PermissionObjectTypeAttachment = "attachment"
	PermissionObjectTypeRole       = "role"
	PermissionObjectTypeShelf      = "shelf"

	PermissionRelationOwner           = "owner"
	PermissionRelationAdmin           = "admin"
	PermissionRelationWriter          = "writer"
	PermissionRelationReader          = "reader"
	PermissionRelationParent          = "parent"
	PermissionRelationParentDirectory = "parent_directory"
	PermissionRelationParentNote      = "parent_note"

	PermissionRelationGrantRead      = "grant_read"
	PermissionRelationGrantWrite     = "grant_write"
	PermissionRelationGrantAdmin     = "grant_admin"
	PermissionRelationDelegateRead   = "delegate_read"
	PermissionRelationDelegateWrite  = "delegate_write"
	PermissionRelationDelegateAdmin  = "delegate_admin"
	PermissionRelationGrantMember    = "grant_member"
	PermissionRelationDelegateMember = "delegate_member"

	PermissionSubjectRelationMember = "member"
)

// shareablePermissionRelations lists the relations that PermissionService
// accepts for each resource type.  Hierarchical relations (parent,
// parent_directory, parent_note) and owner are managed by the resource
// patch/creation flows and are intentionally not writable via /permissions.
var shareablePermissionRelations = map[proto.PermissionObjectType]map[string]struct{}{
	proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_NOTE: relationSet(
		PermissionRelationAdmin,
		PermissionRelationWriter,
		PermissionRelationReader,
		PermissionRelationGrantRead,
		PermissionRelationGrantWrite,
		PermissionRelationGrantAdmin,
		PermissionRelationDelegateRead,
		PermissionRelationDelegateWrite,
		PermissionRelationDelegateAdmin,
	),
	proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_DIRECTORY: relationSet(
		PermissionRelationAdmin,
		PermissionRelationWriter,
		PermissionRelationReader,
		PermissionRelationGrantRead,
		PermissionRelationGrantWrite,
		PermissionRelationGrantAdmin,
		PermissionRelationDelegateRead,
		PermissionRelationDelegateWrite,
		PermissionRelationDelegateAdmin,
	),
	proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_SHELF: relationSet(
		PermissionRelationAdmin,
		PermissionRelationWriter,
		PermissionRelationReader,
		PermissionRelationGrantRead,
		PermissionRelationGrantWrite,
		PermissionRelationGrantAdmin,
		PermissionRelationDelegateRead,
		PermissionRelationDelegateWrite,
		PermissionRelationDelegateAdmin,
	),
	proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ROLE: relationSet(
		PermissionRelationGrantMember,
		PermissionRelationDelegateMember,
	),
}

func relationSet(relations ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(relations))
	for _, relation := range relations {
		set[relation] = struct{}{}
	}
	return set
}

// setPermissionGRPCError maps gRPC status codes to REST responses.
func setPermissionGRPCError(c *gin.Context, err error, op string) {
	if grpcErr, ok := status.FromError(err); ok {
		switch grpcErr.Code() {
		case codes.InvalidArgument:
			utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("%s: %w", op, err))
			return
		case codes.PermissionDenied:
			utils.SetGinError(c, http.StatusForbidden, fmt.Errorf("%s: %w", op, err))
			return
		case codes.NotFound:
			utils.SetGinError(c, http.StatusNotFound, fmt.Errorf("%s: %w", op, err))
			return
		}
	}
	utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}

// GetPermissionsQuery defines query parameters for fetching permissions.
type GetPermissionsQuery struct {
	ObjectType string `form:"object_type" binding:"required" enums:"note,directory,shelf,role" example:"note"`
	ObjectId   string `form:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PermissionSubjectRequest defines the subject side of a relationship.
//
// Role subjects may set OptionalRelation to "member" (role:<id>#member).
// User subjects must leave it empty.
type PermissionSubjectRequest struct {
	ObjectType       string `json:"object_type" binding:"required" enums:"user,role" example:"user"`
	ObjectId         string `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	OptionalRelation string `json:"optional_relation,omitempty" binding:"omitempty" enums:"member" example:"member"`
}

// PermissionResourceRequest defines an optional explicit resource for a relationship.
type PermissionResourceRequest struct {
	ObjectType string `json:"object_type" binding:"required" enums:"note,directory,shelf,role" example:"note"`
	ObjectId   string `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PermissionRelationshipRequest defines one relationship tuple
// like note:42#reader@user:24 where 42 and 24 are the actual uuids.
type PermissionRelationshipRequest struct {
	Relation string                     `json:"relation" binding:"required" enums:"admin,writer,reader,grant_read,grant_write,grant_admin,delegate_read,delegate_write,delegate_admin,grant_member,delegate_member" example:"reader"`
	Subject  PermissionSubjectRequest   `json:"subject" binding:"required"`
	Resource *PermissionResourceRequest `json:"resource,omitempty"`
}

// CreatePermissionBody defines request body for creating a single permission relationship.
type CreatePermissionBody struct {
	ObjectType   string                        `json:"object_type" binding:"required" enums:"note,directory,shelf,role" example:"note"`
	ObjectId     string                        `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Relationship PermissionRelationshipRequest `json:"relationship" binding:"required"`
}

// DeletePermissionBody defines request body for deleting a single permission relationship.
type DeletePermissionBody struct {
	ObjectType   string                        `json:"object_type" binding:"required" enums:"note,directory,shelf,role" example:"note"`
	ObjectId     string                        `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Relationship PermissionRelationshipRequest `json:"relationship" binding:"required"`
}

// ReplacePermissionsBody defines request body for replacing all permission relationships.
type ReplacePermissionsBody struct {
	ObjectType    string                          `json:"object_type" binding:"required" enums:"note,directory,shelf,role" example:"note"`
	ObjectId      string                          `json:"object_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Relationships []PermissionRelationshipRequest `json:"relationships" binding:"required"`
}

// PermissionsReply is the REST response containing the full permission set for an object.
type PermissionsReply struct {
	ObjectType    string                        `json:"object_type" enums:"PERMISSION_OBJECT_TYPE_UNSPECIFIED,PERMISSION_OBJECT_TYPE_NOTE,PERMISSION_OBJECT_TYPE_DIRECTORY,PERMISSION_OBJECT_TYPE_USER,PERMISSION_OBJECT_TYPE_ATTACHMENT,PERMISSION_OBJECT_TYPE_ROLE,PERMISSION_OBJECT_TYPE_SHELF"`
	ObjectId      string                        `json:"object_id"`
	Relationships []PermissionRelationshipReply `json:"relationships"`
}

// parsePermissionObjectType normalizes a REST `object_type` value and maps it
// to the protobuf enum expected by PermissionService.
//
// Accepted values are either the short REST name ("note", "directory", ...)
// or the fully-qualified protobuf enum name
// ("PERMISSION_OBJECT_TYPE_NOTE", ...).
func parsePermissionObjectType(objectType string) (proto.PermissionObjectType, error) {
	normalized := strings.ToUpper(strings.TrimSpace(objectType))
	normalized = strings.TrimPrefix(normalized, "PERMISSION_OBJECT_TYPE_")
	switch normalized {
	case "NOTE":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_NOTE, nil
	case "DIRECTORY":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_DIRECTORY, nil
	case "USER":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_USER, nil
	case "ATTACHMENT":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ATTACHMENT, nil
	case "ROLE":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ROLE, nil
	case "SHELF":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_SHELF, nil
	case "UNSPECIFIED":
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_UNSPECIFIED, nil
	default:
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_UNSPECIFIED, fmt.Errorf("invalid object_type: %s", objectType)
	}
}

// parsePermissionResourceType validates an object type that can own a
// permission relationship managed by PermissionService.
func parsePermissionResourceType(objectType string) (proto.PermissionObjectType, error) {
	parsed, err := parsePermissionObjectType(objectType)
	if err != nil {
		return parsed, err
	}

	if _, ok := shareablePermissionRelations[parsed]; !ok {
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_UNSPECIFIED,
			fmt.Errorf("object_type %s does not support permission management", objectType)
	}
	return parsed, nil
}

// parsePermissionSubjectType validates a subject type.  The share API accepts
// users and roles; role subjects use the role:<id>#member userset form.
func parsePermissionSubjectType(objectType string) (proto.PermissionObjectType, error) {
	parsed, err := parsePermissionObjectType(objectType)
	if err != nil {
		return parsed, err
	}

	switch parsed {
	case proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_USER,
		proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ROLE:
		return parsed, nil
	default:
		return proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_UNSPECIFIED,
			fmt.Errorf("subject object_type must be user or role, got %s", objectType)
	}
}

// parsePermissionRelation validates that relation is writable for resourceType.
func parsePermissionRelation(resourceType proto.PermissionObjectType, relation string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(relation))

	allowed, ok := shareablePermissionRelations[resourceType]
	if !ok {
		return "", fmt.Errorf("object_type %s does not support permission management", resourceType)
	}
	if _, ok := allowed[normalized]; !ok {
		return "", fmt.Errorf("relation %q is not writable for object_type %s", relation, resourceType)
	}
	return normalized, nil
}

// normalizeSubjectOptionalRelation validates and normalizes the userset
// qualifier.  User subjects must not carry one; role subjects default to
// "member".
func normalizeSubjectOptionalRelation(subjectType proto.PermissionObjectType, optionalRelation string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(optionalRelation))

	switch subjectType {
	case proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_USER:
		if normalized != "" {
			return "", fmt.Errorf("optional_relation is only valid for role subjects")
		}
		return "", nil
	case proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ROLE:
		if normalized == "" {
			return PermissionSubjectRelationMember, nil
		}
		if normalized != PermissionSubjectRelationMember {
			return "", fmt.Errorf("role subjects only support optional_relation=%q", PermissionSubjectRelationMember)
		}
		return normalized, nil
	default:
		return "", fmt.Errorf("subject object_type must be user or role, got %s", subjectType)
	}
}

// permissionSubjectRequestToProto maps a REST subject payload into a
// protobuf PermissionSubject.
func permissionSubjectRequestToProto(subject PermissionSubjectRequest) (*proto.PermissionSubject, error) {
	subjectType, err := parsePermissionSubjectType(subject.ObjectType)
	if err != nil {
		return nil, err
	}

	optionalRelation, err := normalizeSubjectOptionalRelation(subjectType, subject.OptionalRelation)
	if err != nil {
		return nil, err
	}

	return &proto.PermissionSubject{
		ObjectType:       subjectType,
		ObjectId:         subject.ObjectId,
		OptionalRelation: optionalRelation,
	}, nil
}

// permissionResourceRequestToProto maps a REST resource payload into a
// protobuf PermissionResource.
func permissionResourceRequestToProto(resource PermissionResourceRequest) (*proto.PermissionResource, error) {
	resourceType, err := parsePermissionResourceType(resource.ObjectType)
	if err != nil {
		return nil, err
	}

	return &proto.PermissionResource{
		ObjectType: resourceType,
		ObjectId:   resource.ObjectId,
	}, nil
}

// permissionRelationshipRequestToProto maps a REST relationship payload into a
// protobuf PermissionRelationship for the target resource.
//
// The optional relationship-level resource must match objectType/objectId of
// the request; it is accepted for compatibility with the gRPC shape but is not
// required by REST callers.
func permissionRelationshipRequestToProto(
	objectType proto.PermissionObjectType,
	objectId string,
	relationship PermissionRelationshipRequest,
) (*proto.PermissionRelationship, error) {
	relation, err := parsePermissionRelation(objectType, relationship.Relation)
	if err != nil {
		return nil, err
	}

	subject, err := permissionSubjectRequestToProto(relationship.Subject)
	if err != nil {
		return nil, err
	}

	if relationship.Resource != nil {
		resource, err := permissionResourceRequestToProto(*relationship.Resource)
		if err != nil {
			return nil, err
		}
		if resource.GetObjectType() != objectType || resource.GetObjectId() != objectId {
			return nil, fmt.Errorf("relationship.resource must match object_type/object_id of the request")
		}
	}

	return &proto.PermissionRelationship{
		Relation: relation,
		Subject:  subject,
		Resource: &proto.PermissionResource{
			ObjectType: objectType,
			ObjectId:   objectId,
		},
	}, nil
}

// permissionsReplyFromProto converts the gRPC PermissionsResponse into the
// REST PermissionsReply shape.
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
// @Param object_type query string true "Object type" Enums(note, directory, shelf, role)
// @Param object_id query string true "Object ID"
// @Success 200 {object} PermissionsReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [get]
func (pc *PermissionController) GetPermissions(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetPermissionsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	objectType, err := parsePermissionResourceType(query.ObjectType)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	response, err := (*pc.PermissionService).GetPermissions(c, &proto.GetPermissionsRequest{
		ObjectType: objectType,
		ObjectId:   query.ObjectId,
		UserId:     user.ID,
	})
	if err != nil {
		setPermissionGRPCError(c, err, "get permissions")
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
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [post]
func (pc *PermissionController) CreatePermission(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreatePermissionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	objectType, err := parsePermissionResourceType(body.ObjectType)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	relationship, err := permissionRelationshipRequestToProto(objectType, body.ObjectId, body.Relationship)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	response, err := (*pc.PermissionService).CreatePermission(c, &proto.CreatePermissionRequest{
		ObjectType:   objectType,
		ObjectId:     body.ObjectId,
		Relationship: relationship,
		UserId:       user.ID,
	})
	if err != nil {
		setPermissionGRPCError(c, err, "create permission")
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
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [delete]
func (pc *PermissionController) DeletePermission(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DeletePermissionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	objectType, err := parsePermissionResourceType(body.ObjectType)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	relationship, err := permissionRelationshipRequestToProto(objectType, body.ObjectId, body.Relationship)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	response, err := (*pc.PermissionService).DeletePermission(c, &proto.DeletePermissionRequest{
		ObjectType:   objectType,
		ObjectId:     body.ObjectId,
		Relationship: relationship,
		UserId:       user.ID,
	})
	if err != nil {
		setPermissionGRPCError(c, err, "delete permission")
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
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [put]
func (pc *PermissionController) ReplacePermissions(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body ReplacePermissionsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	objectType, err := parsePermissionResourceType(body.ObjectType)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	relationships := make([]*proto.PermissionRelationship, 0, len(body.Relationships))
	for _, relationshipBody := range body.Relationships {
		relationship, err := permissionRelationshipRequestToProto(objectType, body.ObjectId, relationshipBody)
		if err != nil {
			utils.SetGinError(c, http.StatusBadRequest, err)
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
		setPermissionGRPCError(c, err, "replace permissions")
		return
	}

	c.JSON(http.StatusOK, permissionsReplyFromProto(response))
}
