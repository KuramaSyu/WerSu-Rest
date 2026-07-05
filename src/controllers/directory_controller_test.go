package controllers

import (
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
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockDirectoryMinimalNoteStream is a lightweight fake that implements the
// grpc.ServerStreamingClient interface for MinimalNote, used by
// GetNotesOfDirectory in the directory gRPC service.
type mockDirectoryMinimalNoteStream struct {
	ctx   context.Context
	notes []*proto.MinimalNote
	index int
}

// Recv returns the next minimal note until EOF to end the stream.
func (m *mockDirectoryMinimalNoteStream) Recv() (*proto.MinimalNote, error) {
	if m.index >= len(m.notes) {
		return nil, io.EOF
	}
	note := m.notes[m.index]
	m.index++
	return note, nil
}

func (m *mockDirectoryMinimalNoteStream) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}

func (m *mockDirectoryMinimalNoteStream) Trailer() metadata.MD {
	return metadata.MD{}
}

func (m *mockDirectoryMinimalNoteStream) CloseSend() error {
	return nil
}

func (m *mockDirectoryMinimalNoteStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

func (m *mockDirectoryMinimalNoteStream) SendMsg(interface{}) error {
	return nil
}

func (m *mockDirectoryMinimalNoteStream) RecvMsg(interface{}) error {
	return nil
}

// mockDirectoryServiceClient is a configurable fake that captures request
// payloads and returns canned responses for DirectoryService RPCs.
type mockDirectoryServiceClient struct {
	getDirectory        func(ctx context.Context, in *proto.GetDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error)
	getDirectories      func(ctx context.Context, in *proto.GetDirectoriesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Directory], error)
	createDirectory     func(ctx context.Context, in *proto.CreateDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error)
	patchDirectory      func(ctx context.Context, in *proto.AlterDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error)
	deleteDirectory     func(ctx context.Context, in *proto.DeleteDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error)
	getNotesOfDirectory func(ctx context.Context, in *proto.GetNotesOfDirectoryRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.MinimalNote], error)
}

func (m *mockDirectoryServiceClient) GetDirectory(ctx context.Context, in *proto.GetDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error) {
	return m.getDirectory(ctx, in, opts...)
}

func (m *mockDirectoryServiceClient) GetDirectories(ctx context.Context, in *proto.GetDirectoriesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.Directory], error) {
	return m.getDirectories(ctx, in, opts...)
}

func (m *mockDirectoryServiceClient) CreateDirectory(ctx context.Context, in *proto.CreateDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error) {
	return m.createDirectory(ctx, in, opts...)
}

func (m *mockDirectoryServiceClient) PatchDirectory(ctx context.Context, in *proto.AlterDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error) {
	return m.patchDirectory(ctx, in, opts...)
}

func (m *mockDirectoryServiceClient) DeleteDirectory(ctx context.Context, in *proto.DeleteDirectoryRequest, opts ...grpc.CallOption) (*proto.Directory, error) {
	return m.deleteDirectory(ctx, in, opts...)
}

func (m *mockDirectoryServiceClient) GetNotesOfDirectory(ctx context.Context, in *proto.GetNotesOfDirectoryRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.MinimalNote], error) {
	return m.getNotesOfDirectory(ctx, in, opts...)
}

// setupDirectoryRouter builds a minimal Gin router with session middleware
// and the routes required for the directory tests.
func setupDirectoryRouter(client proto.DirectoryServiceClient) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("discord_auth", store))
	// Inject a logged-in user into the session for each request.
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("user", models.User{ID: "user-1"})
		_ = session.Save()
		c.Next()
	})

	controller := NewDirectoryController(&client)
	api := router.Group("/api")
	directories := api.Group("/directories")
	{
		directory := directories.Group("/:id")
		{
			directory.GET("/notes", controller.GetNotesOfDirectory)
		}
	}

	return router
}

func TestGetNotesOfDirectory(t *testing.T) {
	updatedAt := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	stream := &mockDirectoryMinimalNoteStream{
		notes: []*proto.MinimalNote{
			{
				Id:              "note-1",
				Title:           "First",
				AuthorId:        "user-1",
				UpdatedAt:       timestamppb.New(updatedAt),
				StrippedContent: "First content",
			},
			{
				Id:              "note-2",
				Title:           "Second",
				AuthorId:        "user-2",
				UpdatedAt:       timestamppb.New(updatedAt.Add(time.Hour)),
				StrippedContent: "Second content",
			},
		},
	}

	client := &mockDirectoryServiceClient{}
	client.getNotesOfDirectory = func(ctx context.Context, in *proto.GetNotesOfDirectoryRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.MinimalNote], error) {
		if in.GetDirectoryId() != "dir-1" {
			t.Fatalf("expected directory_id dir-1, got %s", in.GetDirectoryId())
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		if in.Limit == nil || *in.Limit != 5 {
			t.Fatalf("expected limit 5, got %v", in.Limit)
		}
		if in.Offset == nil || *in.Offset != 2 {
			t.Fatalf("expected offset 2, got %v", in.Offset)
		}
		return stream, nil
	}

	router := setupDirectoryRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/directories/dir-1/notes?limit=5&offset=2", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	var payload []MinimalNote
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(payload) != 2 {
		t.Fatalf("expected 2 notes, got %d", len(payload))
	}

	if payload[0].Id != "note-1" || payload[0].Title != "First" {
		t.Fatalf("unexpected first note payload: %+v", payload[0])
	}
	if payload[0].UpdatedAt != updatedAt.Format(time.RFC3339) {
		t.Fatalf("unexpected updated_at: %v", payload[0].UpdatedAt)
	}
	if payload[1].Id != "note-2" || payload[1].Title != "Second" {
		t.Fatalf("unexpected second note payload: %+v", payload[1])
	}
}

func TestGetNotesOfDirectoryDefaultsLimitTo20(t *testing.T) {
	client := &mockDirectoryServiceClient{}
	client.getNotesOfDirectory = func(ctx context.Context, in *proto.GetNotesOfDirectoryRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.MinimalNote], error) {
		if in.GetDirectoryId() != "dir-2" {
			t.Fatalf("expected directory_id dir-2, got %s", in.GetDirectoryId())
		}
		if in.Limit == nil || *in.Limit != 20 {
			t.Fatalf("expected default limit 20, got %v", in.Limit)
		}
		if in.Offset != nil {
			t.Fatalf("expected no offset, got %v", *in.Offset)
		}
		return &mockDirectoryMinimalNoteStream{notes: []*proto.MinimalNote{}}, nil
	}

	router := setupDirectoryRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/directories/dir-2/notes", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	var payload []MinimalNote
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("expected empty list, got %d notes", len(payload))
	}
}
