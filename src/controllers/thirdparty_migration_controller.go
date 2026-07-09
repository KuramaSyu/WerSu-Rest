package controllers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

// BookstackImportChunkSize is the size of each zip slice forwarded to the
// BookstackBookImport gRPC stream (1 MiB).
const BookstackImportChunkSize = 1 << 20

// ThirdpartyMigrationController exposes REST endpoints that import content
// from third-party documentation tools (currently BookStack) into the project.
//
// Endpoints are thin: they accept a file via multipart/form-data, slice it into
// fixed-size chunks and forward them to the matching gRPC client-streaming RPC.
type ThirdpartyMigrationController struct {
	MigrationsService *proto.ThirdpartyMigrationsServiceClient
}

// NewThirdpartyMigrationController creates a controller bound to the
// ThirdpartyMigrationsService gRPC client.
func NewThirdpartyMigrationController(
	migrationsService *proto.ThirdpartyMigrationsServiceClient,
) *ThirdpartyMigrationController {
	return &ThirdpartyMigrationController{MigrationsService: migrationsService}
}

// BookstackImportedChapterReply mirrors the gRPC BookstackImportedChapter
// message but with plain Go types suitable for JSON serialization.
type BookstackImportedChapterReply struct {
	DirectoryId   string `json:"directory_id"`
	ChapterName   string `json:"chapter_name"`
	PagesImported int32  `json:"pages_imported"`
}

// BookstackBookImportReply mirrors the gRPC BookstackBookImportResponse
// message. PagesImported and AttachmentsUploaded are included even when zero so
// callers can tell at a glance what the import produced.
type BookstackBookImportReply struct {
	BookDirectoryId     string                          `json:"book_directory_id"`
	Chapters            []BookstackImportedChapterReply `json:"chapters"`
	PagesImported       int32                           `json:"pages_imported"`
	AttachmentsUploaded int32                           `json:"attachments_uploaded"`
}

func bookstackBookImportReplyFromProto(
	resp *proto.BookstackBookImportResponse,
) BookstackBookImportReply {
	if resp == nil {
		return BookstackBookImportReply{}
	}

	chapters := make([]BookstackImportedChapterReply, 0, len(resp.GetChapters()))
	for _, chapter := range resp.GetChapters() {
		chapters = append(chapters, BookstackImportedChapterReply{
			DirectoryId:   chapter.GetDirectoryId(),
			ChapterName:   chapter.GetChapterName(),
			PagesImported: chapter.GetPagesImported(),
		})
	}

	return BookstackBookImportReply{
		BookDirectoryId:     resp.GetBookDirectoryId(),
		Chapters:            chapters,
		PagesImported:       resp.GetPagesImported(),
		AttachmentsUploaded: resp.GetAttachmentsUploaded(),
	}
}

// @Summary Import a BookStack book zip
// @Description Accepts a BookStack book zip via multipart/form-data and forwards it to the BookstackBookImport gRPC streaming RPC in 1 MiB chunks. Returns the created book directory and per-chapter import stats on success.
// @Tags migrations
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "BookStack book zip archive"
// @Success 200 {object} BookstackBookImportReply
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Security CookieAuth
// @Router /migrations/import_bookstack_book [post]
func (mc *ThirdpartyMigrationController) ImportBookstackBook(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing 'file' multipart field: %w", err))
		return
	}

	fileReader, err := file.Open()
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to open uploaded file: %w", err))
		return
	}
	defer fileReader.Close()

	stream, err := (*mc.MigrationsService).BookstackBookImport(c)
	if err != nil {
		SetGinError(c, http.StatusBadGateway, fmt.Errorf("failed to open bookstack import stream: %w", err))
		return
	}

	buf := make([]byte, BookstackImportChunkSize)
	first := true
	for {
		n, readErr := io.ReadFull(fileReader, buf)
		if n > 0 {
			// Copy out of the reusable buffer so the next ReadFull can't
			// mutate the payload after we hand it to the gRPC stream.
			payload := make([]byte, n)
			copy(payload, buf[:n])

			chunk := &proto.BookstackBookImportChunk{Content: payload}
			if first {
				chunk.UserId = user.ID
				first = false
			}

			if sendErr := stream.Send(chunk); sendErr != nil {
				SetGinError(c, http.StatusBadGateway, fmt.Errorf("failed to send zip chunk: %w", sendErr))
				return
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to read uploaded file: %w", readErr))
			return
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		SetGinError(c, http.StatusBadGateway, fmt.Errorf("bookstack import failed: %w", err))
		return
	}

	c.JSON(http.StatusOK, bookstackBookImportReplyFromProto(resp))
}
