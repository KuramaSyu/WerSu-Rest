package controllers

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNoteResponseToProtoIncludesReferences(t *testing.T) {
	resp := &proto.NoteResponse{
		Note: &proto.Note{
			Id:        "note-1",
			Title:     "index",
			Content:   "{{@note-2#details}}",
			AuthorId:  "user-1",
			UpdatedAt: timestamppb.New(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)),
		},
		References: []*proto.NoteReference{
			{NoteId: "note-2", Section: "details", Content: "resolved section"},
			{NoteId: "note-3", Content: "whole note"},
			{NoteId: "note-4", Section: "secret", Content: "Error: no permission"},
		},
	}

	reply := NoteResponseToProto(resp)

	if len(reply.References) != 3 {
		t.Fatalf("references: want 3, got %d", len(reply.References))
	}
	if got := reply.References[0]; got.NoteId != "note-2" || got.Section != "details" || got.Content != "resolved section" {
		t.Fatalf("first reference mismatch: %+v", got)
	}
	if got := reply.References[1]; got.NoteId != "note-3" || got.Section != "" || got.Content != "whole note" {
		t.Fatalf("whole-note reference mismatch: %+v", got)
	}
	if got := reply.References[2]; got.NoteId != "note-4" || got.Content != "Error: no permission" {
		t.Fatalf("unauthorized reference mismatch: %+v", got)
	}
}

func TestGetNoteQueryIncludeReferences(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newContext := func(url string) *gin.Context {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest("GET", url, nil)
		return ctx
	}

	var omitted GetNoteQuery
	if err := newContext("/notes/note-1").ShouldBindQuery(&omitted); err != nil {
		t.Fatalf("bind omitted query: %v", err)
	}
	if omitted.IncludeReferences != nil {
		t.Fatalf("omitted include_references should stay nil, got %v", *omitted.IncludeReferences)
	}

	var disabled GetNoteQuery
	if err := newContext("/notes/note-1?include_references=false").ShouldBindQuery(&disabled); err != nil {
		t.Fatalf("bind include_references=false: %v", err)
	}
	if disabled.IncludeReferences == nil || *disabled.IncludeReferences {
		t.Fatalf("include_references=false was not bound correctly")
	}

	var enabled GetNoteQuery
	if err := newContext("/notes/note-1?include_references=true").ShouldBindQuery(&enabled); err != nil {
		t.Fatalf("bind include_references=true: %v", err)
	}
	if enabled.IncludeReferences == nil || !*enabled.IncludeReferences {
		t.Fatalf("include_references=true was not bound correctly")
	}
}
