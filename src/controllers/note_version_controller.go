package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

// NoteVersionController handles note versioning routes.
type NoteVersionController struct {
	NoteVersionService *proto.NoteVersionServiceClient
}

func NewNoteVersionController(noteVersionService *proto.NoteVersionServiceClient) *NoteVersionController {
	return &NoteVersionController{NoteVersionService: noteVersionService}
}

// NoteVersionSummaryReply represents one note version entry in REST responses.
type NoteVersionSummaryReply struct {
	VersionId    string    `json:"version_id"`
	NoteId       string    `json:"note_id"`
	VersionIndex int64     `json:"version_index"`
	CreatedAt    time.Time `json:"created_at"`
	AuthorId     string    `json:"author_id"`
	IsSnapshot   bool      `json:"is_snapshot"`
	SnapshotId   string    `json:"snapshot_id"`
}

// NoteVersionContentReply represents a specific note version content in REST responses.
type NoteVersionContentReply struct {
	NoteId       string    `json:"note_id"`
	VersionIndex int64     `json:"version_index"`
	CreatedAt    time.Time `json:"created_at"`
	AuthorId     string    `json:"author_id"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
}

type GetNoteVersionsQuery struct {
	Limit  *int32 `form:"limit" binding:"omitempty"`
	Offset *int32 `form:"offset" binding:"omitempty"`
}

func noteVersionSummaryReplyFromProto(summary *proto.NoteVersionSummary) NoteVersionSummaryReply {
	createdAt := time.Time{}
	if summary.GetCreatedAt() != nil {
		createdAt = summary.GetCreatedAt().AsTime()
	}

	return NoteVersionSummaryReply{
		VersionId:    summary.GetVersionId(),
		NoteId:       summary.GetNoteId(),
		VersionIndex: summary.GetVersionIndex(),
		CreatedAt:    createdAt,
		AuthorId:     summary.GetAuthorId(),
		IsSnapshot:   summary.GetIsSnapshot(),
		SnapshotId:   summary.GetSnapshotId(),
	}
}

func noteVersionContentReplyFromProto(content *proto.NoteVersionContent) NoteVersionContentReply {
	createdAt := time.Time{}
	if content.GetCreatedAt() != nil {
		createdAt = content.GetCreatedAt().AsTime()
	}

	return NoteVersionContentReply{
		NoteId:       content.GetNoteId(),
		VersionIndex: content.GetVersionIndex(),
		CreatedAt:    createdAt,
		AuthorId:     content.GetAuthorId(),
		Title:        content.GetTitle(),
		Content:      content.GetContent(),
	}
}

// ListNoteVersions godoc
// @Summary List note versions
// @Description Fetch note version summaries via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param note_id path string true "Note ID (UUIDv7)"
// @Param limit query int false "Maximum results to return"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} []NoteVersionSummaryReply
// @Failure 400 {object} map[string]string
// @Router /notes/{note_id}/versions [get]
func (uc *NoteVersionController) ListNoteVersions(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	noteId := c.Params.ByName("note_id")
	if noteId == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing note ID"))
		return
	}

	var query GetNoteVersionsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	grpcRequest := proto.GetNoteVersionsRequest{
		NoteId: noteId,
		Limit:  query.Limit,
		Offset: query.Offset,
		UserId: user.ID,
	}

	stream, err := (*uc.NoteVersionService).GetNoteVersions(c, &grpcRequest)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch note versions via gRPC service: %w", err))
		return
	}

	versions := make([]NoteVersionSummaryReply, 0)
	for {
		version, err := stream.Recv()
		if err != nil {
			break
		}
		versions = append(versions, noteVersionSummaryReplyFromProto(version))
	}

	c.JSON(http.StatusOK, versions)
}

// GetNoteVersionContent godoc
// @Summary Get note version content
// @Description Fetch note version content via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param note_id path string true "Note ID (UUIDv7)"
// @Param version_index path int true "Version index"
// @Success 200 {object} NoteVersionContentReply
// @Failure 400 {object} map[string]string
// @Router /notes/{note_id}/versions/{version_index} [get]
func (uc *NoteVersionController) GetNoteVersionContent(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	noteId := c.Params.ByName("note_id")
	if noteId == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing note ID"))
		return
	}

	versionIndexParam := c.Params.ByName("version_index")
	versionIndex, err := strconv.ParseInt(versionIndexParam, 10, 64)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid version index"))
		return
	}

	grpcRequest := proto.GetNoteVersionContentRequest{
		NoteId:       noteId,
		VersionIndex: versionIndex,
		UserId:       user.ID,
	}

	content, err := (*uc.NoteVersionService).GetNoteVersionContent(c, &grpcRequest)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch note version content via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, noteVersionContentReplyFromProto(content))
}

// RestoreNoteVersion godoc
// @Summary Restore note version
// @Description Restore note version via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param note_id path string true "Note ID (UUIDv7)"
// @Param version_index path int true "Version index"
// @Success 200 {object} NoteReply
// @Failure 400 {object} map[string]string
// @Router /notes/{note_id}/versions/{version_index}/restore [post]
func (uc *NoteVersionController) RestoreNoteVersion(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	noteId := c.Params.ByName("note_id")
	if noteId == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing note ID"))
		return
	}

	versionIndexParam := c.Params.ByName("version_index")
	versionIndex, err := strconv.ParseInt(versionIndexParam, 10, 64)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid version index"))
		return
	}

	grpcRequest := proto.RestoreNoteVersionRequest{
		NoteId:       noteId,
		VersionIndex: versionIndex,
		UserId:       user.ID,
	}

	note, err := (*uc.NoteVersionService).RestoreNoteVersion(c, &grpcRequest)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to restore note version via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, NoteReplyFromProto(note))
}
