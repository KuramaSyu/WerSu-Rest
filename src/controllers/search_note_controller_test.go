package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockNoteServiceClient captures the SearchNotes request so tests can assert
// how the REST controller mapped query string -> proto.NoteSearchFilter.
type mockNoteServiceClient struct {
	searchNotes func(ctx context.Context, in *proto.GetSearchNotesRequest, opts ...grpc.CallOption) (*proto.NotesReply, error)
}

func (m *mockNoteServiceClient) GetNote(context.Context, *proto.GetNoteRequest, ...grpc.CallOption) (*proto.NoteResponse, error) {
	return nil, nil
}
func (m *mockNoteServiceClient) PostNote(context.Context, *proto.PostNoteRequest, ...grpc.CallOption) (*proto.Note, error) {
	return nil, nil
}
func (m *mockNoteServiceClient) PatchNote(context.Context, *proto.AlterNoteRequest, ...grpc.CallOption) (*proto.Note, error) {
	return nil, nil
}
func (m *mockNoteServiceClient) DeleteNote(context.Context, *proto.DeleteNoteRequest, ...grpc.CallOption) (*proto.Note, error) {
	return nil, nil
}
func (m *mockNoteServiceClient) SearchNotes(ctx context.Context, in *proto.GetSearchNotesRequest, opts ...grpc.CallOption) (*proto.NotesReply, error) {
	return m.searchNotes(ctx, in, opts...)
}

// setupSearchNoteRouter wires a minimal Gin router with session middleware
// and only the /notes/search route. The user is pre-authenticated.
func setupSearchNoteRouter(client proto.NoteServiceClient) *gin.Engine {
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

	controller := NewSearchNoteController(&client)
	api := router.Group("/api")
	api.GET("/notes/search", controller.GetNotes)
	return router
}

// equalStringSlice returns true when both slices contain the same strings
// in the same order. nil and empty are treated as equal so a missing param
// can be compared against an unset struct field.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSearchNotesBindsRepeatedQueryParams verifies that Go's net/url and Gin's
// ShouldBindQuery really expand repeated query keys into []string fields
// (i.e. ?include_directory_ids=a&include_directory_ids=b becomes ["a","b"]),
// and that the controller forwards them into proto.NoteSearchFilter.
func TestSearchNotesBindsRepeatedQueryParams(t *testing.T) {
	var got *proto.GetSearchNotesRequest
	client := &mockNoteServiceClient{
		searchNotes: func(_ context.Context, in *proto.GetSearchNotesRequest, _ ...grpc.CallOption) (*proto.NotesReply, error) {
			got = in
			return &proto.NotesReply{}, nil
		},
	}

	dateFrom := "2026-01-01T00:00:00Z"
	dateUntil := "2026-12-31T23:59:59Z"

	url := "/api/notes/search" +
		"?search_type=keyword" +
		"&query=python" +
		"&limit=20&offset=0" +
		"&date_from=" + dateFrom +
		"&date_until=" + dateUntil +
		"&include_directory_ids=dir-a" +
		"&include_directory_ids=dir-b" +
		"&exclude_directory_ids=dir-c" +
		"&include_shelf_ids=shelf-a" +
		"&exclude_shelf_ids=shelf-b" +
		"&include_tag_ids=tag-a" +
		"&include_tag_ids=tag-b" +
		"&exclude_tag_ids=tag-c"

	router := setupSearchNoteRouter(client)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got == nil {
		t.Fatal("SearchNotes RPC was not invoked")
	}

	// Top-level scalar fields.
	if got.GetQuery() != "python" {
		t.Errorf("query: want python, got %q", got.GetQuery())
	}
	if got.GetLimit() != 20 {
		t.Errorf("limit: want 20, got %d", got.GetLimit())
	}
	if got.GetOffset() != 0 {
		t.Errorf("offset: want 0, got %d", got.GetOffset())
	}
	if got.GetUserId() != "user-1" {
		t.Errorf("user_id: want user-1, got %q", got.GetUserId())
	}
	if got.SearchType != proto.GetSearchNotesRequest_FullTextTitle {
		t.Errorf("search_type: want FullTextTitle, got %v", got.SearchType)
	}

	if got.Filter == nil {
		t.Fatal("expected Filter to be populated, got nil")
	}

	// Repeated string fields: each repeated key must arrive as a separate slice entry.
	wantInclDirs := []string{"dir-a", "dir-b"}
	if !equalStringSlice(got.Filter.GetIncludeDirectoryIds(), wantInclDirs) {
		t.Errorf("include_directory_ids: want %v, got %v", wantInclDirs, got.Filter.GetIncludeDirectoryIds())
	}
	if !equalStringSlice(got.Filter.GetExcludeDirectoryIds(), []string{"dir-c"}) {
		t.Errorf("exclude_directory_ids: want [dir-c], got %v", got.Filter.GetExcludeDirectoryIds())
	}
	if !equalStringSlice(got.Filter.GetIncludeShelfIds(), []string{"shelf-a"}) {
		t.Errorf("include_shelf_ids: want [shelf-a], got %v", got.Filter.GetIncludeShelfIds())
	}
	if !equalStringSlice(got.Filter.GetExcludeShelfIds(), []string{"shelf-b"}) {
		t.Errorf("exclude_shelf_ids: want [shelf-b], got %v", got.Filter.GetExcludeShelfIds())
	}
	wantInclTags := []string{"tag-a", "tag-b"}
	if !equalStringSlice(got.Filter.GetIncludeTagIds(), wantInclTags) {
		t.Errorf("include_tag_ids: want %v, got %v", wantInclTags, got.Filter.GetIncludeTagIds())
	}
	if !equalStringSlice(got.Filter.GetExcludeTagIds(), []string{"tag-c"}) {
		t.Errorf("exclude_tag_ids: want [tag-c], got %v", got.Filter.GetExcludeTagIds())
	}

	// date bounds parsed from RFC3339 strings.
	wantFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wantUntil := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	if got.Filter.DateFrom == nil || !got.Filter.DateFrom.AsTime().Equal(wantFrom) {
		t.Errorf("date_from: want %v, got %v", wantFrom, got.Filter.GetDateFrom())
	}
	if got.Filter.DateUntil == nil || !got.Filter.DateUntil.AsTime().Equal(wantUntil) {
		t.Errorf("date_until: want %v, got %v", wantUntil, got.Filter.GetDateUntil())
	}
}

// TestSearchNotesBindsSingleQueryParam checks the simpler case where a
// repeated-key field is supplied exactly once. Go's url.Values keeps the
// trailing []string, so the slice should still be length 1.
func TestSearchNotesBindsSingleQueryParam(t *testing.T) {
	var got *proto.GetSearchNotesRequest
	client := &mockNoteServiceClient{
		searchNotes: func(_ context.Context, in *proto.GetSearchNotesRequest, _ ...grpc.CallOption) (*proto.NotesReply, error) {
			got = in
			return &proto.NotesReply{}, nil
		},
	}

	router := setupSearchNoteRouter(client)
	req := httptest.NewRequest(http.MethodGet,
		"/api/notes/search?search_type=keyword&include_tag_ids=only-one", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !equalStringSlice(got.Filter.GetIncludeTagIds(), []string{"only-one"}) {
		t.Errorf("include_tag_ids: want [only-one], got %v", got.Filter.GetIncludeTagIds())
	}
	if len(got.Filter.GetExcludeTagIds()) != 0 {
		t.Errorf("exclude_tag_ids should be empty, got %v", got.Filter.GetExcludeTagIds())
	}
}

// TestSearchNotesInvalidDateReturnsBadRequest ensures bad date strings
// surface as a structured HTTP 400 (with an `error` summary and a per-field
// `details` map) instead of silently being forwarded.
func TestSearchNotesInvalidDateReturnsBadRequest(t *testing.T) {
	called := false
	client := &mockNoteServiceClient{
		searchNotes: func(_ context.Context, _ *proto.GetSearchNotesRequest, _ ...grpc.CallOption) (*proto.NotesReply, error) {
			called = true
			return &proto.NotesReply{}, nil
		},
	}

	router := setupSearchNoteRouter(client)
	req := httptest.NewRequest(http.MethodGet,
		"/api/notes/search?search_type=keyword&date_from=not-a-date", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("SearchNotes RPC must not be invoked when date_from is invalid")
	}

	var body struct {
		Error   string            `json:"error"`
		Details map[string]string `json:"details"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode 400 body: %v", err)
	}
	if body.Error == "" {
		t.Errorf("expected a non-empty summary `error`, got %q", body.Error)
	}
	msg, ok := body.Details["date_from"]
	if !ok {
		t.Fatalf("expected details.date_from, got %+v", body.Details)
	}
	if !strings.Contains(msg, "not-a-date") {
		t.Errorf("details.date_from should echo the offending value, got %q", msg)
	}
	if !strings.Contains(msg, "RFC3339") {
		t.Errorf("details.date_from should list accepted formats, got %q", msg)
	}
}

// TestSearchNotesReportsAllInvalidDates confirms that the controller reports
// every malformed date parameter in a single response (no early bail-out),
// so clients can fix them in one round-trip.
func TestSearchNotesReportsAllInvalidDates(t *testing.T) {
	called := false
	client := &mockNoteServiceClient{
		searchNotes: func(_ context.Context, _ *proto.GetSearchNotesRequest, _ ...grpc.CallOption) (*proto.NotesReply, error) {
			called = true
			return &proto.NotesReply{}, nil
		},
	}
	router := setupSearchNoteRouter(client)
	req := httptest.NewRequest(http.MethodGet,
		"/api/notes/search?search_type=keyword&date_from=bad-from&date_until=bad-until",
		nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("SearchNotes RPC must not be invoked when date bounds are invalid")
	}

	var body struct {
		Details map[string]string `json:"details"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode 400 body: %v", err)
	}
	if _, ok := body.Details["date_from"]; !ok {
		t.Errorf("expected details.date_from, got %+v", body.Details)
	}
	if _, ok := body.Details["date_until"]; !ok {
		t.Errorf("expected details.date_until, got %+v", body.Details)
	}
}

// searchDateCase drives /notes/search with a custom date_from string and
// returns the parsed time the controller forwarded to the gRPC layer.
//
// The raw value is percent-encoded so `+` survives transport intact (a
// literal `+` in a query string would otherwise be decoded as a space).
func searchDateCase(t *testing.T, raw string) (time.Time, int) {
	t.Helper()
	var got *proto.GetSearchNotesRequest
	client := &mockNoteServiceClient{
		searchNotes: func(_ context.Context, in *proto.GetSearchNotesRequest, _ ...grpc.CallOption) (*proto.NotesReply, error) {
			got = in
			return &proto.NotesReply{}, nil
		},
	}
	router := setupSearchNoteRouter(client)
	target := "/api/notes/search?search_type=keyword&date_from=" + url.QueryEscape(raw)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if got == nil || got.Filter == nil || got.Filter.DateFrom == nil {
		return time.Time{}, rec.Code
	}
	return got.Filter.DateFrom.AsTime(), rec.Code
}

// Test multiple, ISO-similar date formats
func TestSearchNotesAcceptsLenientDateFormats(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Time
	}{
		{"rfc3339_with_z", "2026-01-02T15:04:05Z", time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"rfc3339_with_offset", "2026-01-02T15:04:05+02:00", time.Date(2026, 1, 2, 13, 4, 5, 0, time.UTC)},
		{"rfc3339_nano", "2026-01-02T15:04:05.123Z", time.Date(2026, 1, 2, 15, 4, 5, 123_000_000, time.UTC)},
		{"datetime_no_z_seconds", "2026-01-02T15:04:05", time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"datetime_no_z_minutes_only", "2026-01-02T15:04", time.Date(2026, 1, 2, 15, 4, 0, 0, time.UTC)},
		{"date_only", "2026-01-02", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, code := searchDateCase(t, tc.raw)
			if code != http.StatusOK {
				t.Fatalf("expected status 200 for %q, got %d", tc.raw, code)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parsed time for %q: want %v, got %v", tc.raw, tc.want, got)
			}
		})
	}
}

// TestSearchNotesRejectsGarbageDate ensures genuinely bad inputs still 400
// instead of silently being treated as zero.
func TestSearchNotesRejectsGarbageDate(t *testing.T) {
	cases := []string{
		"yesterday",
		"2026/01/02",
		"2026-13-40",
		"15:04:05",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, code := searchDateCase(t, raw)
			if code != http.StatusBadRequest {
				t.Fatalf("expected status 400 for %q, got %d", raw, code)
			}
		})
	}
}

// reference timestamppb to keep the import even if a future edit removes
// every direct usage above.
var _ = timestamppb.New
