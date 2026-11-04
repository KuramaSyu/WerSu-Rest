package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockPermissionServiceClient struct {
	getPermissions     func(ctx context.Context, in *proto.GetPermissionsRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error)
	createPermission   func(ctx context.Context, in *proto.CreatePermissionRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error)
	deletePermission   func(ctx context.Context, in *proto.DeletePermissionRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error)
	replacePermissions func(ctx context.Context, in *proto.ReplacePermissionsRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error)
}

func (m *mockPermissionServiceClient) GetPermissions(ctx context.Context, in *proto.GetPermissionsRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
	return m.getPermissions(ctx, in, opts...)
}

func (m *mockPermissionServiceClient) CreatePermission(ctx context.Context, in *proto.CreatePermissionRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
	return m.createPermission(ctx, in, opts...)
}

func (m *mockPermissionServiceClient) DeletePermission(ctx context.Context, in *proto.DeletePermissionRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
	return m.deletePermission(ctx, in, opts...)
}

func (m *mockPermissionServiceClient) ReplacePermissions(ctx context.Context, in *proto.ReplacePermissionsRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
	return m.replacePermissions(ctx, in, opts...)
}

func setupPermissionRouter(client proto.PermissionServiceClient) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("discord_auth", store))
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("user", models.User{ID: "user-1"})
		_ = session.Save()
		c.Next()
	})

	controller := NewPermissionController(&client)
	api := router.Group("/api")
	permissions := api.Group("/permissions")
	{
		permissions.GET("", controller.GetPermissions)
		permissions.POST("", controller.CreatePermission)
		permissions.DELETE("", controller.DeletePermission)
		permissions.PUT("", controller.ReplacePermissions)
	}
	return router
}

func TestCreatePermissionSupportsShelfAndRoleSubject(t *testing.T) {
	client := &mockPermissionServiceClient{}
	client.createPermission = func(ctx context.Context, in *proto.CreatePermissionRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		if in.GetObjectType() != proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_SHELF {
			t.Fatalf("expected shelf object type, got %s", in.GetObjectType())
		}
		if in.GetObjectId() != "shelf-1" {
			t.Fatalf("expected shelf-1, got %s", in.GetObjectId())
		}
		relationship := in.GetRelationship()
		if relationship.GetRelation() != PermissionRelationGrantRead {
			t.Fatalf("expected grant_read, got %s", relationship.GetRelation())
		}
		if relationship.GetSubject().GetObjectType() != proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ROLE {
			t.Fatalf("expected role subject, got %s", relationship.GetSubject().GetObjectType())
		}
		if relationship.GetSubject().GetOptionalRelation() != PermissionSubjectRelationMember {
			t.Fatalf("expected member optional relation, got %s", relationship.GetSubject().GetOptionalRelation())
		}
		if relationship.GetResource().GetObjectType() != proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_SHELF ||
			relationship.GetResource().GetObjectId() != "shelf-1" {
			t.Fatalf("expected relationship resource to be shelf:shelf-1, got %+v", relationship.GetResource())
		}

		return &proto.PermissionsResponse{
			ObjectType: in.GetObjectType(),
			ObjectId:   in.GetObjectId(),
			Relationships: []*proto.PermissionRelationship{{
				Relation: relationship.GetRelation(),
				Subject:  relationship.GetSubject(),
				Resource: relationship.GetResource(),
			}},
		}, nil
	}

	router := setupPermissionRouter(client)
	body, _ := json.Marshal(map[string]any{
		"object_type": "shelf",
		"object_id":   "shelf-1",
		"relationship": map[string]any{
			"relation": "grant_read",
			"subject": map[string]any{
				"object_type":       "role",
				"object_id":         "role-1",
				"optional_relation": "member",
			},
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/permissions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload PermissionsReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.ObjectType != "PERMISSION_OBJECT_TYPE_SHELF" || payload.ObjectId != "shelf-1" {
		t.Fatalf("unexpected permissions reply: %+v", payload)
	}
	if len(payload.Relationships) != 1 || payload.Relationships[0].Subject.OptionalRelation != "member" {
		t.Fatalf("unexpected relationships: %+v", payload.Relationships)
	}
}

func TestCreatePermissionRejectsUserSubjectWithOptionalRelation(t *testing.T) {
	client := &mockPermissionServiceClient{}
	router := setupPermissionRouter(client)
	body, _ := json.Marshal(map[string]any{
		"object_type": "note",
		"object_id":   "note-1",
		"relationship": map[string]any{
			"relation": "reader",
			"subject": map[string]any{
				"object_type":       "user",
				"object_id":         "user-2",
				"optional_relation": "member",
			},
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/permissions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestCreatePermissionRejectsStructuralRelation(t *testing.T) {
	client := &mockPermissionServiceClient{}
	router := setupPermissionRouter(client)
	body, _ := json.Marshal(map[string]any{
		"object_type": "note",
		"object_id":   "note-1",
		"relationship": map[string]any{
			"relation": "parent_directory",
			"subject": map[string]any{
				"object_type": "role",
				"object_id":   "role-1",
			},
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/permissions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestCreatePermissionMapsGrpcInvalidArgumentTo400(t *testing.T) {
	client := &mockPermissionServiceClient{}
	client.createPermission = func(ctx context.Context, in *proto.CreatePermissionRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
		return nil, status.Error(codes.InvalidArgument, "unsupported relation")
	}

	router := setupPermissionRouter(client)
	body, _ := json.Marshal(map[string]any{
		"object_type": "note",
		"object_id":   "note-1",
		"relationship": map[string]any{
			"relation": "reader",
			"subject": map[string]any{
				"object_type": "user",
				"object_id":   "user-2",
			},
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/permissions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetPermissionsSupportsRoleObjects(t *testing.T) {
	client := &mockPermissionServiceClient{}
	client.getPermissions = func(ctx context.Context, in *proto.GetPermissionsRequest, opts ...grpc.CallOption) (*proto.PermissionsResponse, error) {
		if in.GetObjectType() != proto.PermissionObjectType_PERMISSION_OBJECT_TYPE_ROLE {
			t.Fatalf("expected role object type, got %s", in.GetObjectType())
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		return &proto.PermissionsResponse{
			ObjectType: in.GetObjectType(),
			ObjectId:   in.GetObjectId(),
		}, nil
	}

	router := setupPermissionRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/permissions?object_type=role&object_id=role-1", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}
}
