// Package controllers -- ShelfController exposes the gRPC ShelfService
// over REST.
//
// A shelf is a flat (non-hierarchical) grouping of books
// (directories).  Books can sit on multiple shelves.  The proto
// exposes a `BootstrapStrategy` on CreateShelf so the caller can
// ask the server to also create the default zettelkasten books
// and rules in the same call.
//
// All optional string fields are pointers so we can distinguish
// "field omitted" (leave unchanged) from "field set to empty
// string" (explicit clear) on the PATCH path.
package controllers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ShelfController wires REST routes to the gRPC ShelfService.
type ShelfController struct {
	ShelfService *proto.ShelfServiceClient
}

// NewShelfController creates a controller bound to a ShelfService client.
func NewShelfController(shelfService *proto.ShelfServiceClient) *ShelfController {
	return &ShelfController{ShelfService: shelfService}
}

// setShelfGRPCError maps gRPC errors to REST status codes.
func setShelfGRPCError(c *gin.Context, err error, op string) {
	if grpcErr, ok := status.FromError(err); ok {
		switch grpcErr.Code() {
		case codes.PermissionDenied:
			utils.SetGinError(c, http.StatusForbidden, fmt.Errorf("%s: %w", op, err))
			return
		case codes.NotFound:
			utils.SetGinError(c, http.StatusNotFound, fmt.Errorf("%s: %w", op, err))
			return
		case codes.InvalidArgument:
			utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("%s: %w", op, err))
			return
		}
	}
	utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}

// ShelfReply is the REST representation of a shelf.
//
// `BookIds` is omitted when the caller did not opt in via
// `?include_books=true`, mirroring the proto's empty-by-default
// convention.
type ShelfReply struct {
	Id           string   `json:"id"`
	Slug         string   `json:"slug"`
	DisplayName  string   `json:"display_name"`
	Description  string   `json:"description"`
	ImageUrl     string   `json:"image_url"`
	ReadmeNoteId string   `json:"readme_note_id,omitempty"`
	BookIds      []string `json:"book_ids,omitempty"`
}

// BootstrapResultReply describes the side-effects of a CreateShelf
// call that ran with a non-NONE bootstrap strategy.
type BootstrapResultReply struct {
	CreatedDirectoryIds []string `json:"created_directory_ids,omitempty"`
	CreatedRuleId       string   `json:"created_rule_id,omitempty"`
	Description         string   `json:"description,omitempty"`
}

// CreateShelfReply is the response shape when a shelf was just
// created.  `BootstrapResult` is omitted when no strategy ran.
type CreateShelfReply struct {
	Shelf           ShelfReply            `json:"shelf"`
	BootstrapResult *BootstrapResultReply `json:"bootstrap_result,omitempty"`
}

// DeleteShelfReply is the response shape for a DeleteShelf call.
// When `Dry` was requested, the response carries the would-be
// cascade instead of an empty body.
type DeleteShelfReply struct {
	Dry             bool     `json:"dry"`
	AffectedBookIds []string `json:"affected_book_ids,omitempty"`
	BindingCount    int32    `json:"binding_count"`
}

// BookIdsReply carries a flat list of book ids (shelf -> books).
type BookIdsReply struct {
	BookIds []string `json:"book_ids"`
}

// ShelfIdsReply carries a flat list of shelf ids (book -> shelves).
type ShelfIdsReply struct {
	ShelfIds []string `json:"shelf_ids"`
}

// CreateShelfBody is the JSON body for creating a shelf.
//
// `BootstrapStrategy` accepts the proto enum string label
// (e.g. "BOOTSTRAP_STRATEGY_ZETTELKASTEN") or the integer
// representation.  Empty / unknown values map to NONE.
type CreateShelfBody struct {
	Slug              string  `json:"slug" binding:"required" example:"engineering"`
	DisplayName       *string `json:"display_name,omitempty" example:"Engineering"`
	Description       *string `json:"description,omitempty" example:"Shared notes for engineering team"`
	ImageUrl          *string `json:"image_url,omitempty" example:"https://cdn.example.com/engineering.png"`
	ReadmeNoteId      *string `json:"readme_note_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	BootstrapStrategy string  `json:"bootstrap_strategy,omitempty" example:"BOOTSTRAP_STRATEGY_NONE"`
}

// UpdateShelfBody is the JSON body for updating a shelf.
//
// All optional fields are pointers so we can distinguish "field
// omitted" (leave unchanged) from "field set to empty string"
// (explicit clear).  The proto uses `optional` fields for the
// same reason.
type UpdateShelfBody struct {
	Id           string  `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	Slug         *string `json:"slug,omitempty" example:"engineering"`
	DisplayName  *string `json:"display_name,omitempty" example:"Engineering"`
	Description  *string `json:"description,omitempty" example:"Shared notes for engineering team"`
	ImageUrl     *string `json:"image_url,omitempty" example:"https://cdn.example.com/engineering.png"`
	ReadmeNoteId *string `json:"readme_note_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// DeleteShelfBody is the JSON body for deleting a shelf.
//
// `Dry` returns the would-be cascade instead of deleting.
type DeleteShelfBody struct {
	Id  string `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	Dry bool   `json:"dry,omitempty" example:"false"`
}

// SetBooksBody replaces the set of books on a shelf.
type SetBooksBody struct {
	ShelfId string   `json:"shelf_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	BookIds []string `json:"book_ids" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// AttachBookBody attaches a single book to a shelf.
type AttachBookBody struct {
	ShelfId string `json:"shelf_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	BookId  string `json:"book_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// DetachBookBody detaches a single book from a shelf.
type DetachBookBody struct {
	ShelfId string `json:"shelf_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	BookId  string `json:"book_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// GetShelfQuery controls which related entities the server embeds.
type GetShelfQuery struct {
	IncludeBooks bool `form:"include_books" example:"true"`
}

// ListShelvesQuery is the query string for ListShelves.
type ListShelvesQuery struct {
	Limit        *int32 `form:"limit" example:"20"`
	Offset       *int32 `form:"offset" example:"0"`
	IncludeBooks bool   `form:"include_books" example:"false"`
}

// GetShelvesBody wraps the explicit-id read; the gRPC service
// uses repeated ids rather than a streamed URL pattern.
type GetShelvesBody struct {
	Ids          []string `json:"ids" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	IncludeBooks bool     `json:"include_books,omitempty" example:"false"`
}

// shelfReplyFromProto converts a gRPC Shelf into the REST shape.
func shelfReplyFromProto(shelf *proto.Shelf) ShelfReply {
	return ShelfReply{
		Id:           shelf.GetId(),
		Slug:         shelf.GetSlug(),
		DisplayName:  shelf.GetDisplayName(),
		Description:  shelf.GetDescription(),
		ImageUrl:     shelf.GetImageUrl(),
		ReadmeNoteId: shelf.GetReadmeNoteId(),
		BookIds:      shelf.GetBookIds(),
	}
}

// bootstrapResultFromProto converts a gRPC BootstrapResult into REST.
func bootstrapResultFromProto(br *proto.BootstrapResult) *BootstrapResultReply {
	if br == nil {
		return nil
	}
	return &BootstrapResultReply{
		CreatedDirectoryIds: br.GetCreatedDirectoryIds(),
		CreatedRuleId:       br.GetCreatedRuleId(),
		Description:         br.GetDescription(),
	}
}

// bootstrapStrategyFromString parses a string or integer label into
// the proto enum.  Returns UNSPECIFIED for unknown / empty values.
func bootstrapStrategyFromString(s string) proto.BootstrapStrategy {
	if s == "" {
		return proto.BootstrapStrategy_BOOTSTRAP_STRATEGY_UNSPECIFIED
	}
	if v, ok := proto.BootstrapStrategy_value[s]; ok {
		return proto.BootstrapStrategy(v)
	}
	return proto.BootstrapStrategy_BOOTSTRAP_STRATEGY_UNSPECIFIED
}

// GetShelf godoc
// @Summary Get shelf by ID
// @Description Fetches a single shelf via the gRPC service.
// @Tags shelves
// @Accept json
// @Produce json
// @Param id path string true "Shelf ID"
// @Param include_books query bool false "Include book IDs the shelf binds"
// @Success 200 {object} ShelfReply
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/{id} [get]
func (sc *ShelfController) GetShelf(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Param("id")
	if id == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing shelf ID"))
		return
	}

	var query GetShelfQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	resp, err := (*sc.ShelfService).GetShelf(c, &proto.GetShelfRequest{
		UserId:       user.ID,
		Id:           id,
		IncludeBooks: query.IncludeBooks,
	})
	if err != nil {
		setShelfGRPCError(c, err, "fetch shelf")
		return
	}

	c.JSON(http.StatusOK, shelfReplyFromProto(resp.GetShelf()))
}

// GetShelves godoc
// @Summary Get shelves by IDs
// @Description Fetches multiple shelves by ID via the gRPC service.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body GetShelvesBody true "Shelf IDs to fetch"
// @Success 200 {object} []ShelfReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/by-ids [post]
func (sc *ShelfController) GetShelves(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body GetShelvesBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*sc.ShelfService).GetShelves(c, &proto.GetShelvesRequest{
		UserId:       user.ID,
		Ids:          body.Ids,
		IncludeBooks: body.IncludeBooks,
	})
	if err != nil {
		setShelfGRPCError(c, err, "fetch shelves")
		return
	}

	shelves := make([]ShelfReply, 0, len(resp.GetShelves()))
	for _, shelf := range resp.GetShelves() {
		shelves = append(shelves, shelfReplyFromProto(shelf))
	}
	c.JSON(http.StatusOK, shelves)
}

// ListShelves godoc
// @Summary List shelves
// @Description Lists shelves with optional pagination via the gRPC service.
// @Tags shelves
// @Accept json
// @Produce json
// @Param limit query int false "Maximum results to return"
// @Param offset query int false "Pagination offset"
// @Param include_books query bool false "Include book IDs each shelf binds"
// @Success 200 {object} []ShelfReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves [get]
func (sc *ShelfController) ListShelves(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query ListShelvesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	resp, err := (*sc.ShelfService).ListShelves(c, &proto.ListShelvesRequest{
		UserId:       user.ID,
		Limit:        query.Limit,
		Offset:       query.Offset,
		IncludeBooks: query.IncludeBooks,
	})
	if err != nil {
		setShelfGRPCError(c, err, "list shelves")
		return
	}

	shelves := make([]ShelfReply, 0, len(resp.GetShelves()))
	for _, shelf := range resp.GetShelves() {
		shelves = append(shelves, shelfReplyFromProto(shelf))
	}
	c.JSON(http.StatusOK, shelves)
}

// CreateShelf godoc
// @Summary Create shelf
// @Description Creates a shelf via the gRPC service.  Optionally runs a
// @Description bootstrap strategy (e.g. zettelkasten) immediately after insert.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body CreateShelfBody true "Create shelf request"
// @Success 200 {object} CreateShelfReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves [post]
func (sc *ShelfController) CreateShelf(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateShelfBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*sc.ShelfService).CreateShelf(c, &proto.CreateShelfRequest{
		UserId:            user.ID,
		Slug:              body.Slug,
		DisplayName:       body.DisplayName,
		Description:       body.Description,
		ImageUrl:          body.ImageUrl,
		ReadmeNoteId:      body.ReadmeNoteId,
		BootstrapStrategy: bootstrapStrategyFromString(body.BootstrapStrategy),
	})
	if err != nil {
		setShelfGRPCError(c, err, "create shelf")
		return
	}

	c.JSON(http.StatusOK, CreateShelfReply{
		Shelf:           shelfReplyFromProto(resp.GetShelf()),
		BootstrapResult: bootstrapResultFromProto(resp.GetBootstrapResult()),
	})
}

// UpdateShelf godoc
// @Summary Update shelf
// @Description Updates an existing shelf via the gRPC service.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body UpdateShelfBody true "Update shelf request"
// @Success 200 {object} ShelfReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves [patch]
func (sc *ShelfController) UpdateShelf(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body UpdateShelfBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*sc.ShelfService).UpdateShelf(c, &proto.UpdateShelfRequest{
		UserId:       user.ID,
		Id:           body.Id,
		Slug:         body.Slug,
		DisplayName:  body.DisplayName,
		Description:  body.Description,
		ImageUrl:     body.ImageUrl,
		ReadmeNoteId: body.ReadmeNoteId,
	})
	if err != nil {
		setShelfGRPCError(c, err, "update shelf")
		return
	}

	c.JSON(http.StatusOK, shelfReplyFromProto(resp.GetShelf()))
}

// DeleteShelf godoc
// @Summary Delete shelf
// @Description Deletes a shelf via the gRPC service.  Set `dry=true` to
// @Description preview the would-be cascade without deleting.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body DeleteShelfBody true "Delete shelf request"
// @Success 200 {object} DeleteShelfReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves [delete]
func (sc *ShelfController) DeleteShelf(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DeleteShelfBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*sc.ShelfService).DeleteShelf(c, &proto.DeleteShelfRequest{
		UserId: user.ID,
		Id:     body.Id,
		Dry:    body.Dry,
	})
	if err != nil {
		setShelfGRPCError(c, err, "delete shelf")
		return
	}

	c.JSON(http.StatusOK, DeleteShelfReply{
		Dry:             resp.GetDry(),
		AffectedBookIds: resp.GetAffectedBookIds(),
		BindingCount:    resp.GetBindingCount(),
	})
}

// SetBooks godoc
// @Summary Replace books on shelf
// @Description Replaces the set of books bound to a shelf.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body SetBooksBody true "Set books request"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/books [put]
func (sc *ShelfController) SetBooks(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body SetBooksBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if _, err := (*sc.ShelfService).SetBooks(c, &proto.SetBooksRequest{
		UserId:  user.ID,
		ShelfId: body.ShelfId,
		BookIds: body.BookIds,
	}); err != nil {
		setShelfGRPCError(c, err, "set books")
		return
	}

	c.Status(http.StatusNoContent)
}

// AttachBook godoc
// @Summary Attach book to shelf
// @Description Attaches a single book to a shelf.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body AttachBookBody true "Attach book request"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/books/attach [post]
func (sc *ShelfController) AttachBook(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body AttachBookBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if _, err := (*sc.ShelfService).AttachBook(c, &proto.AttachBookRequest{
		UserId:  user.ID,
		ShelfId: body.ShelfId,
		BookId:  body.BookId,
	}); err != nil {
		setShelfGRPCError(c, err, "attach book")
		return
	}

	c.Status(http.StatusNoContent)
}

// DetachBook godoc
// @Summary Detach book from shelf
// @Description Detaches a single book from a shelf.
// @Tags shelves
// @Accept json
// @Produce json
// @Param payload body DetachBookBody true "Detach book request"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/books/detach [post]
func (sc *ShelfController) DetachBook(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DetachBookBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if _, err := (*sc.ShelfService).DetachBook(c, &proto.DetachBookRequest{
		UserId:  user.ID,
		ShelfId: body.ShelfId,
		BookId:  body.BookId,
	}); err != nil {
		setShelfGRPCError(c, err, "detach book")
		return
	}

	c.Status(http.StatusNoContent)
}

// GetBooksOfShelf godoc
// @Summary List books on shelf
// @Description Returns the IDs of every book bound to the shelf.
// @Tags shelves
// @Accept json
// @Produce json
// @Param id path string true "Shelf ID"
// @Success 200 {object} BookIdsReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/{id}/books [get]
func (sc *ShelfController) GetBooksOfShelf(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	shelfId := c.Param("id")
	if shelfId == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing shelf ID"))
		return
	}

	resp, err := (*sc.ShelfService).GetBooksOfShelf(c, &proto.GetBooksOfShelfRequest{
		UserId:  user.ID,
		ShelfId: shelfId,
	})
	if err != nil {
		setShelfGRPCError(c, err, "list shelf books")
		return
	}

	c.JSON(http.StatusOK, BookIdsReply{BookIds: resp.GetBookIds()})
}

// GetShelvesOfBook godoc
// @Summary List shelves for book
// @Description Returns the IDs of every shelf the book sits on.
// @Tags shelves
// @Accept json
// @Produce json
// @Param book_id query string true "Book ID"
// @Success 200 {object} ShelfIdsReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shelves/by-book [get]
func (sc *ShelfController) GetShelvesOfBook(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	bookId := c.Query("book_id")
	if bookId == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing book_id"))
		return
	}

	resp, err := (*sc.ShelfService).GetShelvesOfBook(c, &proto.GetShelvesOfBookRequest{
		UserId: user.ID,
		BookId: bookId,
	})
	if err != nil {
		setShelfGRPCError(c, err, "list book shelves")
		return
	}

	c.JSON(http.StatusOK, ShelfIdsReply{ShelfIds: resp.GetShelfIds()})
}

// silence unused-import errors if any subset of routes is dropped
// during future refactors.
var _ = io.EOF
