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

// mockTagServiceClient captures the requests the controller sends to
// the gRPC layer and returns canned responses.  Each field is a func
// so tests can replace just the methods they care about.
type mockTagServiceClient struct {
	createTag func(ctx context.Context, in *proto.CreateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error)
	getTag    func(ctx context.Context, in *proto.GetTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error)
	listTags  func(ctx context.Context, in *proto.ListTagsRequest, opts ...grpc.CallOption) (*proto.TagsResponse, error)
	updateTag func(ctx context.Context, in *proto.UpdateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error)
	deleteTag func(ctx context.Context, in *proto.DeleteTagRequest, opts ...grpc.CallOption) (*proto.DeleteTagResponse, error)
}

func (m *mockTagServiceClient) CreateTag(ctx context.Context, in *proto.CreateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
	return m.createTag(ctx, in, opts...)
}
func (m *mockTagServiceClient) GetTag(ctx context.Context, in *proto.GetTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
	return m.getTag(ctx, in, opts...)
}
func (m *mockTagServiceClient) ListTags(ctx context.Context, in *proto.ListTagsRequest, opts ...grpc.CallOption) (*proto.TagsResponse, error) {
	return m.listTags(ctx, in, opts...)
}
func (m *mockTagServiceClient) UpdateTag(ctx context.Context, in *proto.UpdateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
	return m.updateTag(ctx, in, opts...)
}
func (m *mockTagServiceClient) DeleteTag(ctx context.Context, in *proto.DeleteTagRequest, opts ...grpc.CallOption) (*proto.DeleteTagResponse, error) {
	return m.deleteTag(ctx, in, opts...)
}

// setupTagRouter wires the controller into a minimal Gin router with
// a logged-in user in the session.
func setupTagRouter(client proto.TagServiceClient) *gin.Engine {
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

	controller := NewTagController(&client)
	api := router.Group("/api")
	tags := api.Group("/tags")
	{
		tags.POST("", controller.CreateTag)
		tags.GET("", controller.ListTags)

		tag := tags.Group("/:id")
		{
			tag.GET("", controller.GetTag)
			tag.PATCH("", controller.UpdateTag)
			tag.DELETE("", controller.DeleteTag)
		}
	}

	return router
}

func TestCreateTagSendsExpectedProto(t *testing.T) {
	client := &mockTagServiceClient{}
	client.createTag = func(ctx context.Context, in *proto.CreateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		if in.GetSlug() != "engineering" || in.GetDisplayName() != "Engineering" {
			t.Fatalf("unexpected create payload: %+v", in)
		}
		return &proto.TagResponse{Tag: &proto.MinimalTag{
			Id:          "tag-1",
			Slug:        in.GetSlug(),
			DisplayName: in.GetDisplayName(),
		}}, nil
	}

	router := setupTagRouter(client)
	body, _ := json.Marshal(map[string]any{"slug": "engineering", "display_name": "Engineering"})
	request := httptest.NewRequest(http.MethodPost, "/api/tags", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload TagReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Id != "tag-1" || payload.Slug != "engineering" || payload.DisplayName != "Engineering" {
		t.Fatalf("unexpected tag payload: %+v", payload)
	}
}

func TestCreateTagMissingSlugReturns400(t *testing.T) {
	client := &mockTagServiceClient{}
	router := setupTagRouter(client)
	body, _ := json.Marshal(map[string]any{"display_name": "Engineering"})
	request := httptest.NewRequest(http.MethodPost, "/api/tags", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestCreateTagAlreadyExistsReturns409(t *testing.T) {
	client := &mockTagServiceClient{}
	client.createTag = func(ctx context.Context, in *proto.CreateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		return nil, status.Error(codes.AlreadyExists, "slug taken")
	}

	router := setupTagRouter(client)
	body, _ := json.Marshal(map[string]any{"slug": "engineering", "display_name": "Engineering"})
	request := httptest.NewRequest(http.MethodPost, "/api/tags", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetTagNotFoundReturns404(t *testing.T) {
	client := &mockTagServiceClient{}
	client.getTag = func(ctx context.Context, in *proto.GetTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		if in.GetId() != "0195f8f4-1167-7f89-b5ec-b40a8f08f4cb" {
			t.Fatalf("expected id 0195f8f4-1167-7f89-b5ec-b40a8f08f4cb, got %s", in.GetId())
		}
		return nil, status.Error(codes.NotFound, "no such tag")
	}

	router := setupTagRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/tags/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestListTagsReturnsMappedSlice(t *testing.T) {
	client := &mockTagServiceClient{}
	client.listTags = func(ctx context.Context, in *proto.ListTagsRequest, opts ...grpc.CallOption) (*proto.TagsResponse, error) {
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		return &proto.TagsResponse{Tags: []*proto.MinimalTag{
			{Id: "tag-1", Slug: "a", DisplayName: "A"},
			{Id: "tag-2", Slug: "b", DisplayName: "B"},
		}}, nil
	}

	router := setupTagRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload []TagReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload) != 2 || payload[0].Id != "tag-1" || payload[1].Slug != "b" {
		t.Fatalf("unexpected tags payload: %+v", payload)
	}
}

func TestUpdateTagForwardsOptionalFields(t *testing.T) {
	client := &mockTagServiceClient{}
	client.updateTag = func(ctx context.Context, in *proto.UpdateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		if in.GetId() != "0195f8f4-1167-7f89-b5ec-b40a8f08f4ca" {
			t.Fatalf("expected id 0195f8f4-1167-7f89-b5ec-b40a8f08f4ca, got %s", in.GetId())
		}
		if in.Slug == nil || *in.Slug != "new-slug" {
			t.Fatalf("expected slug new-slug, got %v", in.Slug)
		}
		if in.DisplayName != nil {
			t.Fatalf("expected display_name to stay unset, got %v", *in.DisplayName)
		}
		return &proto.TagResponse{Tag: &proto.MinimalTag{
			Id:          "tag-1",
			Slug:        *in.Slug,
			DisplayName: "Engineering",
		}}, nil
	}

	router := setupTagRouter(client)
	body, _ := json.Marshal(map[string]any{"slug": "new-slug"})
	request := httptest.NewRequest(http.MethodPatch, "/api/tags/0195f8f4-1167-7f89-b5ec-b40a8f08f4ca", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload TagReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Slug != "new-slug" {
		t.Fatalf("unexpected tag payload: %+v", payload)
	}
}

func TestDeleteTagReportsDeleted(t *testing.T) {
	client := &mockTagServiceClient{}
	client.deleteTag = func(ctx context.Context, in *proto.DeleteTagRequest, opts ...grpc.CallOption) (*proto.DeleteTagResponse, error) {
		if in.GetId() != "0195f8f4-1167-7f89-b5ec-b40a8f08f4ca" {
			t.Fatalf("expected id 0195f8f4-1167-7f89-b5ec-b40a8f08f4ca, got %s", in.GetId())
		}
		return &proto.DeleteTagResponse{Deleted: true}, nil
	}

	router := setupTagRouter(client)
	request := httptest.NewRequest(http.MethodDelete, "/api/tags/0195f8f4-1167-7f89-b5ec-b40a8f08f4ca", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload DeleteTagReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !payload.Deleted {
		t.Fatalf("expected deleted=true, got %+v", payload)
	}
}

func TestCreateTagPermissionDeniedReturns403(t *testing.T) {
	client := &mockTagServiceClient{}
	client.createTag = func(ctx context.Context, in *proto.CreateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}

	router := setupTagRouter(client)
	body, _ := json.Marshal(map[string]any{"slug": "engineering", "display_name": "Engineering"})
	request := httptest.NewRequest(http.MethodPost, "/api/tags", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestGetTagPermissionDeniedReturns403(t *testing.T) {
	client := &mockTagServiceClient{}
	client.getTag = func(ctx context.Context, in *proto.GetTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}

	router := setupTagRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/tags/0195f8f4-1167-7f89-b5ec-b40a8f08f4ca", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestListTagsPermissionDeniedReturns403(t *testing.T) {
	client := &mockTagServiceClient{}
	client.listTags = func(ctx context.Context, in *proto.ListTagsRequest, opts ...grpc.CallOption) (*proto.TagsResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}

	router := setupTagRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestUpdateTagPermissionDeniedReturns403(t *testing.T) {
	client := &mockTagServiceClient{}
	client.updateTag = func(ctx context.Context, in *proto.UpdateTagRequest, opts ...grpc.CallOption) (*proto.TagResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}

	router := setupTagRouter(client)
	body, _ := json.Marshal(map[string]any{"slug": "new-slug"})
	request := httptest.NewRequest(http.MethodPatch, "/api/tags/0195f8f4-1167-7f89-b5ec-b40a8f08f4ca", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestDeleteTagPermissionDeniedReturns403(t *testing.T) {
	client := &mockTagServiceClient{}
	client.deleteTag = func(ctx context.Context, in *proto.DeleteTagRequest, opts ...grpc.CallOption) (*proto.DeleteTagResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}

	router := setupTagRouter(client)
	request := httptest.NewRequest(http.MethodDelete, "/api/tags/0195f8f4-1167-7f89-b5ec-b40a8f08f4ca", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", response.Code, response.Body.String())
	}
}
