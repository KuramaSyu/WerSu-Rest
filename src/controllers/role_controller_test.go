package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockRoleServiceClient captures the requests the controller sends
// to the gRPC layer and returns canned responses.  Each field is a
// func so tests can replace just the methods they care about.
type mockRoleServiceClient struct {
	createRole         func(ctx context.Context, in *proto.CreateRoleRequest, opts ...grpc.CallOption) (*proto.Role, error)
	updateRole         func(ctx context.Context, in *proto.UpdateRoleRequest, opts ...grpc.CallOption) (*proto.Role, error)
	deleteRole         func(ctx context.Context, in *proto.DeleteRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	getRole            func(ctx context.Context, in *proto.GetRoleRequest, opts ...grpc.CallOption) (*proto.Role, error)
	getRoles           func(ctx context.Context, in *proto.GetRolesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Role], error)
	addUserToRole      func(ctx context.Context, in *proto.AddUserToRoleRequest, opts ...grpc.CallOption) (*proto.UserRoleMembership, error)
	removeUserFromRole func(ctx context.Context, in *proto.RemoveUserFromRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	getRolesForUser    func(ctx context.Context, in *proto.GetRolesForUserRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Role], error)
	getUsersForRole    func(ctx context.Context, in *proto.GetUsersForRoleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.UserRoleMembership], error)
}

func (m *mockRoleServiceClient) CreateRole(ctx context.Context, in *proto.CreateRoleRequest, opts ...grpc.CallOption) (*proto.Role, error) {
	return m.createRole(ctx, in, opts...)
}
func (m *mockRoleServiceClient) UpdateRole(ctx context.Context, in *proto.UpdateRoleRequest, opts ...grpc.CallOption) (*proto.Role, error) {
	return m.updateRole(ctx, in, opts...)
}
func (m *mockRoleServiceClient) DeleteRole(ctx context.Context, in *proto.DeleteRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.deleteRole(ctx, in, opts...)
}
func (m *mockRoleServiceClient) GetRole(ctx context.Context, in *proto.GetRoleRequest, opts ...grpc.CallOption) (*proto.Role, error) {
	return m.getRole(ctx, in, opts...)
}
func (m *mockRoleServiceClient) GetRoles(ctx context.Context, in *proto.GetRolesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Role], error) {
	return m.getRoles(ctx, in, opts...)
}
func (m *mockRoleServiceClient) AddUserToRole(ctx context.Context, in *proto.AddUserToRoleRequest, opts ...grpc.CallOption) (*proto.UserRoleMembership, error) {
	return m.addUserToRole(ctx, in, opts...)
}
func (m *mockRoleServiceClient) RemoveUserFromRole(ctx context.Context, in *proto.RemoveUserFromRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.removeUserFromRole(ctx, in, opts...)
}
func (m *mockRoleServiceClient) GetRolesForUser(ctx context.Context, in *proto.GetRolesForUserRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Role], error) {
	return m.getRolesForUser(ctx, in, opts...)
}
func (m *mockRoleServiceClient) GetUsersForRole(ctx context.Context, in *proto.GetUsersForRoleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.UserRoleMembership], error) {
	return m.getUsersForRole(ctx, in, opts...)
}

// setupRoleRouter wires the controller into a minimal Gin router
// with a logged-in user in the session.
func setupRoleRouter(client proto.RoleServiceClient) *gin.Engine {
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

	controller := NewRoleController(&client)
	api := router.Group("/api")
	roles := api.Group("/roles")
	{
		roles.POST("", controller.CreateRole)
		roles.GET("", controller.GetRoles)
		roles.PATCH("", controller.UpdateRole)
		roles.DELETE("", controller.DeleteRole)

		role := roles.Group("/:id")
		{
			role.GET("", controller.GetRole)
		}

		roles.POST("/members", controller.AddUserToRole)
		roles.DELETE("/members", controller.RemoveUserFromRole)
		roles.GET("/members", controller.GetUsersForRole)
		roles.GET("/by-user", controller.GetRolesForUser)
	}

	return router
}

// ----- helpers ---------------------------------------------------------

// roleSliceStream yields the given roles in order, then EOF.
type roleSliceStream struct {
	ctx   context.Context
	roles []*proto.Role
	idx   int
}

func (s *roleSliceStream) Recv() (*proto.Role, error) {
	if s.idx >= len(s.roles) {
		return nil, io.EOF
	}
	r := s.roles[s.idx]
	s.idx++
	return r, nil
}

func (s *roleSliceStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *roleSliceStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *roleSliceStream) CloseSend() error             { return nil }
func (s *roleSliceStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
func (s *roleSliceStream) SendMsg(interface{}) error { return nil }
func (s *roleSliceStream) RecvMsg(interface{}) error { return nil }

func TestCreateRoleSendsExpectedProto(t *testing.T) {
	createdAt := time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)
	client := &mockRoleServiceClient{}
	client.createRole = func(ctx context.Context, in *proto.CreateRoleRequest, opts ...grpc.CallOption) (*proto.Role, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		if in.GetName() != "engineering" {
			t.Fatalf("expected name engineering, got %s", in.GetName())
		}
		if in.GetDescription() != "All engineers" {
			t.Fatalf("expected description 'All engineers', got %q", in.GetDescription())
		}
		return &proto.Role{
			Id:          "role-1",
			Name:        in.GetName(),
			CreatedAt:   timestamppb.New(createdAt),
			Description: "All engineers",
		}, nil
	}

	router := setupRoleRouter(client)
	body, _ := json.Marshal(map[string]any{
		"name":        "engineering",
		"description": "All engineers",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload RoleReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Id != "role-1" || payload.Name != "engineering" {
		t.Fatalf("unexpected role payload: %+v", payload)
	}
	if payload.CreatedAt == nil || !payload.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected created_at: %v", payload.CreatedAt)
	}
}

func TestCreateRoleMissingNameReturns400(t *testing.T) {
	client := &mockRoleServiceClient{}
	router := setupRoleRouter(client)
	body, _ := json.Marshal(map[string]any{
		"description": "missing name",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestCreateRolePermissionDeniedReturns403(t *testing.T) {
	client := &mockRoleServiceClient{}
	client.createRole = func(ctx context.Context, in *proto.CreateRoleRequest, opts ...grpc.CallOption) (*proto.Role, error) {
		return nil, status.Error(codes.PermissionDenied, "user is not allowed to create roles")
	}
	router := setupRoleRouter(client)
	body, _ := json.Marshal(map[string]any{"name": "x"})
	request := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetRoleSendsExpectedProto(t *testing.T) {
	client := &mockRoleServiceClient{}
	client.getRole = func(ctx context.Context, in *proto.GetRoleRequest, opts ...grpc.CallOption) (*proto.Role, error) {
		if in.GetUserId() != "user-1" || in.GetId() != "role-1" {
			t.Fatalf("unexpected request: %+v", in)
		}
		return &proto.Role{Id: "role-1", Name: "engineering"}, nil
	}

	router := setupRoleRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/roles/role-1", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}
}

func TestGetRolesStreamsRoles(t *testing.T) {
	stream := &roleSliceStream{
		roles: []*proto.Role{
			{Id: "role-1", Name: "engineering"},
			{Id: "role-2", Name: "marketing"},
		},
	}
	client := &mockRoleServiceClient{}
	client.getRoles = func(ctx context.Context, in *proto.GetRolesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Role], error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("unexpected user_id: %s", in.GetUserId())
		}
		if in.GetFilter() == nil {
			t.Fatalf("expected non-nil filter")
		}
		if in.GetFilter().GetName() != "engineering" {
			t.Fatalf("expected filter.name engineering, got %s", in.GetFilter().GetName())
		}
		return stream, nil
	}

	router := setupRoleRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/roles?name=engineering", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload []RoleReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(payload))
	}
	if payload[0].Id != "role-1" || payload[1].Id != "role-2" {
		t.Fatalf("unexpected role ids: %+v", payload)
	}
}

func TestDeleteRoleReturns204OnSuccess(t *testing.T) {
	client := &mockRoleServiceClient{}
	client.deleteRole = func(ctx context.Context, in *proto.DeleteRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
		if in.GetUserId() != "user-1" || in.GetId() != "role-1" {
			t.Fatalf("unexpected request: %+v", in)
		}
		return &emptypb.Empty{}, nil
	}

	router := setupRoleRouter(client)
	body, _ := json.Marshal(map[string]any{"id": "role-1"})
	request := httptest.NewRequest(http.MethodDelete, "/api/roles", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAddUserToRoleSendsExpectedProto(t *testing.T) {
	client := &mockRoleServiceClient{}
	client.addUserToRole = func(ctx context.Context, in *proto.AddUserToRoleRequest, opts ...grpc.CallOption) (*proto.UserRoleMembership, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected caller user-1, got %s", in.GetUserId())
		}
		if in.GetRoleId() != "role-1" || in.GetSubjectUserId() != "user-2" {
			t.Fatalf("unexpected ids: role=%s subject=%s", in.GetRoleId(), in.GetSubjectUserId())
		}
		return &proto.UserRoleMembership{UserId: "user-2", RoleId: "role-1"}, nil
	}

	router := setupRoleRouter(client)
	body, _ := json.Marshal(map[string]any{
		"role_id":         "role-1",
		"subject_user_id": "user-2",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/roles/members", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload UserRoleMembershipReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.UserId != "user-2" || payload.RoleId != "role-1" {
		t.Fatalf("unexpected membership payload: %+v", payload)
	}
}

func TestAddUserToRoleMissingFieldsReturns400(t *testing.T) {
	client := &mockRoleServiceClient{}
	router := setupRoleRouter(client)
	// missing subject_user_id
	body, _ := json.Marshal(map[string]any{"role_id": "role-1"})
	request := httptest.NewRequest(http.MethodPost, "/api/roles/members", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetRolesForUserRequiresSubjectUserId(t *testing.T) {
	client := &mockRoleServiceClient{}
	router := setupRoleRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/roles/by-user", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetUsersForRoleRequiresRoleId(t *testing.T) {
	client := &mockRoleServiceClient{}
	router := setupRoleRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/roles/members", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}
