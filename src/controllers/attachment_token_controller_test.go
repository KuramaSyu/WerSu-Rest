package controllers

import (
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
	"google.golang.org/protobuf/types/known/emptypb"
)

// mockAttachmentServiceClient captures the requests the attachment
// controller sends to the gRPC layer and returns canned responses.
// Only the methods a test overrides need to be set.
type mockAttachmentServiceClient struct {
	postAttachment           func(ctx context.Context, in *proto.PostAttachmentRequest, opts ...grpc.CallOption) (*proto.Attachment, error)
	getAttachment            func(ctx context.Context, in *proto.GetAttachmentRequest, opts ...grpc.CallOption) (*proto.Attachment, error)
	getAttachmentMetadata    func(ctx context.Context, in *proto.GetAttachmentMetadataRequest, opts ...grpc.CallOption) (*proto.AttachmentMetadata, error)
	deleteAttachment         func(ctx context.Context, in *proto.DeleteAttachmentRequest, opts ...grpc.CallOption) (*proto.DeleteAttachmentResponse, error)
	updateAttachmentMetadata func(ctx context.Context, in *proto.UpdateAttachmentMetadataRequest, opts ...grpc.CallOption) (*proto.AttachmentMetadata, error)
	postAttachmentLink       func(ctx context.Context, in *proto.PostAttachmentLinkRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	deleteAttachmentLink     func(ctx context.Context, in *proto.DeleteAttachmentLinkRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	getAttachmentToken       func(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error)
}

func (m *mockAttachmentServiceClient) PostAttachment(ctx context.Context, in *proto.PostAttachmentRequest, opts ...grpc.CallOption) (*proto.Attachment, error) {
	return m.postAttachment(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) GetAttachment(ctx context.Context, in *proto.GetAttachmentRequest, opts ...grpc.CallOption) (*proto.Attachment, error) {
	return m.getAttachment(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) GetAttachmentMetadata(ctx context.Context, in *proto.GetAttachmentMetadataRequest, opts ...grpc.CallOption) (*proto.AttachmentMetadata, error) {
	return m.getAttachmentMetadata(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) DeleteAttachment(ctx context.Context, in *proto.DeleteAttachmentRequest, opts ...grpc.CallOption) (*proto.DeleteAttachmentResponse, error) {
	return m.deleteAttachment(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) UpdateAttachmentMetadata(ctx context.Context, in *proto.UpdateAttachmentMetadataRequest, opts ...grpc.CallOption) (*proto.AttachmentMetadata, error) {
	return m.updateAttachmentMetadata(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) PostAttachmentLink(ctx context.Context, in *proto.PostAttachmentLinkRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.postAttachmentLink(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) DeleteAttachmentLink(ctx context.Context, in *proto.DeleteAttachmentLinkRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.deleteAttachmentLink(ctx, in, opts...)
}

func (m *mockAttachmentServiceClient) GetAttachmentToken(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error) {
	return m.getAttachmentToken(ctx, in, opts...)
}

// setupAttachmentTokenRouter wires the controller into a minimal Gin
// router. When loggedIn is false the session exists but carries no user,
// which is what UserFromContext sees for an anonymous request.
func setupAttachmentTokenRouter(
	client proto.AttachmentServiceClient,
	loggedIn bool,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("discord_auth", store))
	router.Use(func(c *gin.Context) {
		if loggedIn {
			session := sessions.Default(c)
			session.Set("user", models.User{ID: "user-1"})
			_ = session.Save()
		}
		c.Next()
	})

	controller := NewAttachmentController(&client, nil, nil, nil, "")
	api := router.Group("/api")
	attachments := api.Group("/attachments")
	{
		attachments.GET("/token", controller.GetAttachmentToken)
	}

	return router
}

func TestGetAttachmentTokenSendsExpectedProtoAndReturnsToken(t *testing.T) {
	key := "attachments/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"
	client := &mockAttachmentServiceClient{}
	client.getAttachmentToken = func(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error) {
		if in.GetAttachmentKey() != key {
			t.Fatalf("expected attachment_key %q, got %q", key, in.GetAttachmentKey())
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %q", in.GetUserId())
		}
		return &proto.GetAttachmentTokenResponse{Token: "signed.jwt.value"}, nil
	}

	router := setupAttachmentTokenRouter(client, true)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/attachments/token?key=attachments%2F0195f8f4-1167-7f89-b5ec-b40a8f08f4cb",
		nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload AttachmentTokenReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Token != "signed.jwt.value" {
		t.Fatalf("unexpected token: %q", payload.Token)
	}
}

func TestGetAttachmentTokenPreservesLiteralDotsInKey(t *testing.T) {
	// A key containing a literal dot must reach the gRPC layer untouched;
	// only the URL encoding layer is allowed to translate it.
	key := "attachments/0195.extra"
	client := &mockAttachmentServiceClient{}
	client.getAttachmentToken = func(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error) {
		if in.GetAttachmentKey() != key {
			t.Fatalf("expected attachment_key %q, got %q", key, in.GetAttachmentKey())
		}
		return &proto.GetAttachmentTokenResponse{Token: "t"}, nil
	}

	router := setupAttachmentTokenRouter(client, true)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/attachments/token?key=attachments%2F0195.extra",
		nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetAttachmentTokenMissingKeyReturns400(t *testing.T) {
	client := &mockAttachmentServiceClient{}
	router := setupAttachmentTokenRouter(client, true)
	request := httptest.NewRequest(http.MethodGet, "/api/attachments/token", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetAttachmentTokenNotLoggedInReturns401(t *testing.T) {
	client := &mockAttachmentServiceClient{}
	router := setupAttachmentTokenRouter(client, false)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/attachments/token?key=attachments%2Fx",
		nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetAttachmentTokenPermissionDeniedReturns403(t *testing.T) {
	client := &mockAttachmentServiceClient{}
	client.getAttachmentToken = func(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "user may not view this attachment")
	}

	router := setupAttachmentTokenRouter(client, true)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/attachments/token?key=attachments%2Fx",
		nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetAttachmentTokenNotFoundReturns404(t *testing.T) {
	client := &mockAttachmentServiceClient{}
	client.getAttachmentToken = func(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error) {
		return nil, status.Error(codes.NotFound, "attachment not found")
	}

	router := setupAttachmentTokenRouter(client, true)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/attachments/token?key=attachments%2Fmissing",
		nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetAttachmentTokenBackendUnavailableReturns503(t *testing.T) {
	client := &mockAttachmentServiceClient{}
	client.getAttachmentToken = func(ctx context.Context, in *proto.GetAttachmentTokenRequest, opts ...grpc.CallOption) (*proto.GetAttachmentTokenResponse, error) {
		return nil, status.Error(codes.Unavailable, "backend down")
	}

	router := setupAttachmentTokenRouter(client, true)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/attachments/token?key=attachments%2Fx",
		nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d: %s", response.Code, response.Body.String())
	}
}
