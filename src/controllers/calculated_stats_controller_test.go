package controllers

import (
	"context"
	"encoding/json"
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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockCalculatedStatsServiceClient captures the request the controller
// sends to the gRPC layer and returns a canned response.
type mockCalculatedStatsServiceClient struct {
	getCalculatedStats func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error)
}

func (m *mockCalculatedStatsServiceClient) GetCalculatedStats(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
	return m.getCalculatedStats(ctx, in, opts...)
}

// setupCalculatedStatsRouter wires the controller into a minimal Gin router.
// When loggedIn is false the session exists but carries no user, so the
// handler should answer 401 without calling the gRPC client.
func setupCalculatedStatsRouter(client proto.CalculatedStatsServiceClient, loggedIn bool) *gin.Engine {
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

	controller := NewCalculatedStatsController(&client)
	api := router.Group("/api")
	stats := api.Group("/stats")
	{
		stats.GET("", controller.GetCalculatedStats)
		stats.GET("/:user_id", controller.GetCalculatedStatsForUser)
	}

	return router
}

func TestGetCalculatedStatsReturnsOwnStats(t *testing.T) {
	calculatedAt := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	client := &mockCalculatedStatsServiceClient{}
	client.getCalculatedStats = func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		if in.TargetUserId != nil {
			t.Fatalf("expected target_user_id to be unset for own stats, got %q", in.GetTargetUserId())
		}
		return &proto.GetCalculatedStatsResponse{Stats: &proto.CalculatedStats{
			UserId:        "user-1",
			TotalChars:    12345,
			TotalNotes:    42,
			TotalChapters: 7,
			TotalBooks:    2,
			CalculatedAt:  timestamppb.New(calculatedAt),
		}}, nil
	}

	router := setupCalculatedStatsRouter(client, true)
	request := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload CalculatedStatsReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.UserId != "user-1" || payload.TotalChars != 12345 || payload.TotalNotes != 42 {
		t.Fatalf("unexpected stats payload: %+v", payload)
	}
	if payload.TotalChapters != 7 || payload.TotalBooks != 2 {
		t.Fatalf("unexpected chapter/book counts: %+v", payload)
	}
	if payload.CalculatedAt == nil || !payload.CalculatedAt.Equal(calculatedAt) {
		t.Fatalf("expected calculated_at %s, got %v", calculatedAt, payload.CalculatedAt)
	}
}

func TestGetCalculatedStatsForUserSetsTarget(t *testing.T) {
	targetId := "0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"
	client := &mockCalculatedStatsServiceClient{}
	client.getCalculatedStats = func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected caller user_id user-1, got %s", in.GetUserId())
		}
		if in.TargetUserId == nil || in.GetTargetUserId() != targetId {
			t.Fatalf("expected target_user_id %s, got %v", targetId, in.TargetUserId)
		}
		return &proto.GetCalculatedStatsResponse{Stats: &proto.CalculatedStats{
			UserId:     targetId,
			TotalChars: 7,
			TotalNotes: 3,
		}}, nil
	}

	router := setupCalculatedStatsRouter(client, true)
	request := httptest.NewRequest(http.MethodGet, "/api/stats/"+targetId, nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload CalculatedStatsReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.UserId != targetId || payload.TotalChars != 7 {
		t.Fatalf("unexpected stats payload: %+v", payload)
	}
	if payload.CalculatedAt != nil {
		t.Fatalf("expected omitted calculated_at, got %v", payload.CalculatedAt)
	}
}

func TestGetCalculatedStatsForUserInvalidIDReturns400(t *testing.T) {
	client := &mockCalculatedStatsServiceClient{}
	client.getCalculatedStats = func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
		t.Fatal("gRPC client should not be called for an invalid user id")
		return nil, nil
	}

	router := setupCalculatedStatsRouter(client, true)
	request := httptest.NewRequest(http.MethodGet, "/api/stats/not-a-uuid", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetCalculatedStatsNotFoundReturns404(t *testing.T) {
	client := &mockCalculatedStatsServiceClient{}
	client.getCalculatedStats = func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
		return nil, status.Error(codes.NotFound, "calculated stats not available")
	}

	router := setupCalculatedStatsRouter(client, true)
	request := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetCalculatedStatsPermissionDeniedReturns403(t *testing.T) {
	targetId := "0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"
	client := &mockCalculatedStatsServiceClient{}
	client.getCalculatedStats = func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}

	router := setupCalculatedStatsRouter(client, true)
	request := httptest.NewRequest(http.MethodGet, "/api/stats/"+targetId, nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetCalculatedStatsNotLoggedInReturns401(t *testing.T) {
	client := &mockCalculatedStatsServiceClient{}
	client.getCalculatedStats = func(ctx context.Context, in *proto.GetCalculatedStatsRequest, opts ...grpc.CallOption) (*proto.GetCalculatedStatsResponse, error) {
		t.Fatal("gRPC client should not be called for an unauthenticated request")
		return nil, nil
	}

	router := setupCalculatedStatsRouter(client, false)
	request := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", response.Code, response.Body.String())
	}
}
