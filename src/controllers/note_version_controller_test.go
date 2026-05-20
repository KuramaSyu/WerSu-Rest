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

// mockNoteVersionStream is a lightweight fake that implements the
// grpc.ServerStreamingClient interface used by GetNoteVersions.
// It returns a fixed list of summaries to emulate server streaming.
type mockNoteVersionStream struct {
	ctx       context.Context
	summaries []*proto.NoteVersionSummary
	index     int
}

// Recv returns the next summary until EOF to end the stream.
func (m *mockNoteVersionStream) Recv() (*proto.NoteVersionSummary, error) {
	if m.index >= len(m.summaries) {
		return nil, io.EOF
	}
	note := m.summaries[m.index]
	m.index++
	return note, nil
}

// Header returns empty metadata to satisfy the interface.
func (m *mockNoteVersionStream) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}

// Trailer returns empty metadata to satisfy the interface.
func (m *mockNoteVersionStream) Trailer() metadata.MD {
	return metadata.MD{}
}

// CloseSend is a no-op for the fake stream.
func (m *mockNoteVersionStream) CloseSend() error {
	return nil
}

// Context returns the configured context or a background context.
func (m *mockNoteVersionStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

// SendMsg is unused for server-streaming clients but required by the interface.
func (m *mockNoteVersionStream) SendMsg(interface{}) error {
	return nil
}

// RecvMsg is unused for server-streaming clients but required by the interface.
func (m *mockNoteVersionStream) RecvMsg(interface{}) error {
	return nil
}

// mockNoteVersionServiceClient is a configurable fake that captures
// request payloads and returns canned responses for each RPC.
type mockNoteVersionServiceClient struct {
	getNoteVersions       func(ctx context.Context, in *proto.GetNoteVersionsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.NoteVersionSummary], error)
	getDirectoryActivity  func(ctx context.Context, in *proto.GetDirectoryActivityRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.NoteVersionSummary], error)
	getNoteVersionContent func(ctx context.Context, in *proto.GetNoteVersionContentRequest, opts ...grpc.CallOption) (*proto.NoteVersionContent, error)
	restoreNoteVersion    func(ctx context.Context, in *proto.RestoreNoteVersionRequest, opts ...grpc.CallOption) (*proto.Note, error)
}

// GetNoteVersions forwards to the configured fake handler.
func (m *mockNoteVersionServiceClient) GetNoteVersions(ctx context.Context, in *proto.GetNoteVersionsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.NoteVersionSummary], error) {
	return m.getNoteVersions(ctx, in, opts...)
}

// GetDirectoryActivity forwards to the configured fake handler.
func (m *mockNoteVersionServiceClient) GetDirectoryActivity(ctx context.Context, in *proto.GetDirectoryActivityRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.NoteVersionSummary], error) {
	return m.getDirectoryActivity(ctx, in, opts...)
}

// GetNoteVersionContent forwards to the configured fake handler.
func (m *mockNoteVersionServiceClient) GetNoteVersionContent(ctx context.Context, in *proto.GetNoteVersionContentRequest, opts ...grpc.CallOption) (*proto.NoteVersionContent, error) {
	return m.getNoteVersionContent(ctx, in, opts...)
}

// RestoreNoteVersion forwards to the configured fake handler.
func (m *mockNoteVersionServiceClient) RestoreNoteVersion(ctx context.Context, in *proto.RestoreNoteVersionRequest, opts ...grpc.CallOption) (*proto.Note, error) {
	return m.restoreNoteVersion(ctx, in, opts...)
}

// setupNoteVersionRouter builds a minimal Gin router with session middleware
// and only the versioning routes required for the tests.
func setupNoteVersionRouter(client proto.NoteVersionServiceClient) *gin.Engine {
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

	controller := NewNoteVersionController(&client)
	api := router.Group("/api")
	notes := api.Group("/notes")
	{
		// List summaries for a note's version history.
		notes.GET("/:note_id/versions", controller.ListNoteVersions)
		// Fetch the content for a specific version index.
		notes.GET("/:note_id/versions/:version_index", controller.GetNoteVersionContent)
		// Restore a specific version back to the live note.
		notes.POST("/:note_id/versions/:version_index/restore", controller.RestoreNoteVersion)
	}

	directories := api.Group("/directories")
	{
		directories.GET("/activity", controller.GetDirectoryActivity)
		directory := directories.Group("/:id")
		{
			directory.GET("/activity", controller.GetDirectoryActivity)
		}
	}

	return router
}

func TestListNoteVersions(t *testing.T) {
	// Arrange: create timestamps and a streaming response with two summaries.
	createdAt := time.Date(2025, 10, 5, 12, 30, 0, 0, time.UTC)
	stream := &mockNoteVersionStream{
		summaries: []*proto.NoteVersionSummary{
			{
				VersionId:    "version-1",
				NoteId:       "note-1",
				VersionIndex: 1,
				CreatedAt:    timestamppb.New(createdAt),
				AuthorId:     "user-1",
				IsSnapshot:   false,
				SnapshotId:   "",
			},
			{
				VersionId:    "version-2",
				NoteId:       "note-1",
				VersionIndex: 2,
				CreatedAt:    timestamppb.New(createdAt.Add(time.Hour)),
				AuthorId:     "user-2",
				IsSnapshot:   true,
				SnapshotId:   "snap-1",
			},
		},
	}

	client := &mockNoteVersionServiceClient{}
	// The fake RPC validates that the handler maps query params + session fields
	// into the expected proto request values.
	client.getNoteVersions = func(ctx context.Context, in *proto.GetNoteVersionsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.NoteVersionSummary], error) {
		if in.GetNoteId() != "note-1" {
			t.Fatalf("expected note_id note-1, got %s", in.GetNoteId())
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		if in.Limit == nil || *in.Limit != 2 {
			t.Fatalf("expected limit 2, got %v", in.Limit)
		}
		if in.Offset == nil || *in.Offset != 1 {
			t.Fatalf("expected offset 1, got %v", in.Offset)
		}
		return stream, nil
	}

	// Act: call the REST endpoint with pagination parameters.
	router := setupNoteVersionRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/notes/note-1/versions?limit=2&offset=1", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Assert: ensure HTTP 200 and validate the JSON response payload.
	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	var payload []NoteVersionSummaryReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(payload) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(payload))
	}

	// Validate a subset of fields to ensure proper mapping.
	if payload[0].VersionId != "version-1" || payload[0].VersionIndex != 1 {
		t.Fatalf("unexpected first version payload: %+v", payload[0])
	}

	if !payload[0].CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected created_at: %v", payload[0].CreatedAt)
	}
}

func TestGetDirectoryActivity(t *testing.T) {
	createdAt := time.Date(2025, 9, 20, 14, 10, 0, 0, time.UTC)
	stream := &mockNoteVersionStream{
		summaries: []*proto.NoteVersionSummary{
			{
				VersionId:    "version-10",
				NoteId:       "note-10",
				VersionIndex: 10,
				CreatedAt:    timestamppb.New(createdAt),
				AuthorId:     "user-2",
				IsSnapshot:   false,
				SnapshotId:   "",
			},
			{
				VersionId:    "version-11",
				NoteId:       "note-11",
				VersionIndex: 4,
				CreatedAt:    timestamppb.New(createdAt.Add(30 * time.Minute)),
				AuthorId:     "user-3",
				IsSnapshot:   true,
				SnapshotId:   "snap-2",
			},
		},
	}

	client := &mockNoteVersionServiceClient{}
	client.getDirectoryActivity = func(ctx context.Context, in *proto.GetDirectoryActivityRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[proto.NoteVersionSummary], error) {
		if in.DirectoryId == nil || *in.DirectoryId != "dir-1" {
			t.Fatalf("expected directory_id dir-1, got %v", in.DirectoryId)
		}
		if in.MaxDepth == nil || *in.MaxDepth != 3 {
			t.Fatalf("expected max_depth 3, got %v", in.MaxDepth)
		}
		if in.Limit == nil || *in.Limit != 5 {
			t.Fatalf("expected limit 5, got %v", in.Limit)
		}
		if in.Offset == nil || *in.Offset != 2 {
			t.Fatalf("expected offset 2, got %v", in.Offset)
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		return stream, nil
	}

	router := setupNoteVersionRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/directories/dir-1/activity?max_depth=3&limit=5&offset=2", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	var payload []NoteVersionSummaryReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(payload) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(payload))
	}

	if payload[0].VersionId != "version-10" || payload[0].NoteId != "note-10" {
		t.Fatalf("unexpected first entry payload: %+v", payload[0])
	}
}

func TestGetNoteVersionContent(t *testing.T) {
	// Arrange: configure a version payload and a fake RPC handler.
	createdAt := time.Date(2025, 11, 1, 9, 0, 0, 0, time.UTC)
	client := &mockNoteVersionServiceClient{}
	client.getNoteVersionContent = func(ctx context.Context, in *proto.GetNoteVersionContentRequest, opts ...grpc.CallOption) (*proto.NoteVersionContent, error) {
		if in.GetNoteId() != "note-2" {
			t.Fatalf("expected note_id note-2, got %s", in.GetNoteId())
		}
		if in.GetVersionIndex() != 3 {
			t.Fatalf("expected version_index 3, got %d", in.GetVersionIndex())
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		return &proto.NoteVersionContent{
			NoteId:       "note-2",
			VersionIndex: 3,
			CreatedAt:    timestamppb.New(createdAt),
			AuthorId:     "user-1",
			Title:        "Version title",
			Content:      "Version content",
		}, nil
	}

	// Act: request version content via the REST route.
	router := setupNoteVersionRouter(client)
	request := httptest.NewRequest(http.MethodGet, "/api/notes/note-2/versions/3", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Assert: status is OK and response contains the expected fields.
	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	var payload NoteVersionContentReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if payload.NoteId != "note-2" || payload.VersionIndex != 3 {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	if !payload.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected created_at: %v", payload.CreatedAt)
	}
}

func TestRestoreNoteVersion(t *testing.T) {
	// Arrange: create a restored note response and stub the gRPC method.
	updatedAt := time.Date(2025, 12, 15, 8, 45, 0, 0, time.UTC)
	client := &mockNoteVersionServiceClient{}
	client.restoreNoteVersion = func(ctx context.Context, in *proto.RestoreNoteVersionRequest, opts ...grpc.CallOption) (*proto.Note, error) {
		if in.GetNoteId() != "note-3" {
			t.Fatalf("expected note_id note-3, got %s", in.GetNoteId())
		}
		if in.GetVersionIndex() != 5 {
			t.Fatalf("expected version_index 5, got %d", in.GetVersionIndex())
		}
		if in.GetUserId() != "user-1" {
			t.Fatalf("expected user_id user-1, got %s", in.GetUserId())
		}
		return &proto.Note{
			Id:        "note-3",
			Title:     "Restored",
			Content:   "Restored content",
			UpdatedAt: timestamppb.New(updatedAt),
			AuthorId:  "user-1",
		}, nil
	}

	// Act: call the restore endpoint.
	router := setupNoteVersionRouter(client)
	request := httptest.NewRequest(http.MethodPost, "/api/notes/note-3/versions/5/restore", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Assert: ensure response status and restored fields are returned.
	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	var payload NoteReply
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if payload.Id != "note-3" || payload.Title != "Restored" {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	if !payload.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("unexpected updated_at: %v", payload.UpdatedAt)
	}
}
