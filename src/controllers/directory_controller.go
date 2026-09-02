package controllers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
)

// DirectoryController handles directory routes.
type DirectoryController struct {
	DirectoryService *proto.DirectoryServiceClient
}

func NewDirectoryController(directoryService *proto.DirectoryServiceClient) *DirectoryController {
	return &DirectoryController{DirectoryService: directoryService}
}

// DirectoryReply is the REST representation of a directory.
type DirectoryReply struct {
	Id            string                        `json:"id"`
	Slug          string                        `json:"slug"`
	DisplayName   string                        `json:"display_name"`
	Description   string                        `json:"description"`
	ImageUrl      string                        `json:"image_url"`
	ParentDirIds  []string                      `json:"parent_dir_ids,omitempty"`
	Relationships []PermissionRelationshipReply `json:"relationships"`
	ChildDirIds   []string                      `json:"child_dir_ids,omitempty"`
	ChildNoteIds  []string                      `json:"child_note_ids,omitempty"`
	ShelfIds      []string                      `json:"shelf_ids,omitempty"`
}

type GetDirectoriesQuery struct {
	ParentId          *string `form:"parent_id"`
	Limit             *int32  `form:"limit"`
	Offset            *int32  `form:"offset"`
	IncludeParents    bool    `form:"include_parents"`
	IncludeChildDirs  bool    `form:"include_child_dirs"`
	IncludeChildNotes bool    `form:"include_child_notes"`
	IncludeShelves    bool    `form:"include_shelves"`
}

// GetDirectoryQuery controls which related entities the server embeds in
// the returned `Directory` payload.
type GetDirectoryQuery struct {
	IncludeParents    bool `form:"include_parents"`
	IncludeChildDirs  bool `form:"include_child_dirs"`
	IncludeChildNotes bool `form:"include_child_notes"`
	IncludeShelves    bool `form:"include_shelves"`
}

type GetNotesOfDirectoryQuery struct {
	Limit  *int32 `form:"limit"`
	Offset *int32 `form:"offset"`
}

// defaultLimitForDirectoryNotes is the default `limit` applied to
// `GET /directories/:id/notes` when the client omits the query parameter.
const defaultLimitForDirectoryNotes int32 = 20

// defaultOffsetForDirectoryNotes is the default `offset` applied to
// `GET /directories/:id/notes` when the client omits the query parameter.
const defaultOffsetForDirectoryNotes int32 = 0

type CreateDirectoryBody struct {
	Name        string   `json:"name" binding:"required" example:"engineering"`
	DisplayName *string  `json:"display_name,omitempty" example:"Engineering"`
	Description *string  `json:"description,omitempty" example:"Shared notes for engineering team"`
	ImageUrl    *string  `json:"image_url,omitempty" example:"https://cdn.example.com/engineering.png"`
	ParentIds   []string `json:"parent_ids,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	ShelfIds    []string `json:"shelf_ids,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PatchDirectoryBody mirrors the gRPC AlterDirectoryRequest for REST.
//
// Repeated fields (parent_ids, shelf_ids) are pointers so we can distinguish
// "field omitted" (leave unchanged) from "field set to empty slice" (clear).
// The proto layer uses the same distinction via `oneof` wrappers; see
// `AlterDirectoryRequest_ParentIds` / `AlterDirectoryRequest_ShelfIds`.
type PatchDirectoryBody struct {
	Id          string   `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Name        *string  `json:"name,omitempty" example:"engineering"`
	DisplayName *string  `json:"display_name,omitempty" example:"Engineering"`
	Description *string  `json:"description,omitempty" example:"Shared notes for engineering team"`
	ImageUrl    *string  `json:"image_url,omitempty" example:"https://cdn.example.com/engineering.png"`
	ParentIds   []string `json:"parent_ids,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	ShelfIds    []string `json:"shelf_ids,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

func directoryReplyFromProto(directory *proto.Directory) DirectoryReply {
	relationships := make([]PermissionRelationshipReply, 0, len(directory.GetRelationships()))
	for _, relationship := range directory.GetRelationships() {
		relationships = append(relationships, PermissionRelationshipReplyFromProto(relationship))
	}

	return DirectoryReply{
		Id:            directory.GetId(),
		Slug:          directory.GetSlug(),
		DisplayName:   directory.GetDisplayName(),
		Description:   directory.GetDescription(),
		ImageUrl:      directory.GetImageUrl(),
		ParentDirIds:  directory.GetParentDirIds(),
		Relationships: relationships,
		ChildDirIds:   directory.GetChildDirIds(),
		ChildNoteIds:  directory.GetChildNoteIds(),
		ShelfIds:      directory.GetShelfIds(),
	}
}

// GetDirectory godoc
// @Summary Get directory by ID
// @Description Fetch directory via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param id path string true "Directory ID"
// @Param include_parents query bool false "Include parent directories in the response"
// @Param include_child_dirs query bool false "Include child directory IDs in the response"
// @Param include_child_notes query bool false "Include child note IDs in the response"
// @Param include_shelves query bool false "Include shelf IDs the directory sits on in the response"
// @Success 200 {object} DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories/{id} [get]
func (dc *DirectoryController) GetDirectory(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Params.ByName("id")
	if id == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing directory ID"))
		return
	}

	var query GetDirectoryQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	directory, err := (*dc.DirectoryService).GetDirectory(c, &proto.GetDirectoryRequest{
		Id:                id,
		UserId:            user.ID,
		IncludeParents:    query.IncludeParents,
		IncludeChildDirs:  query.IncludeChildDirs,
		IncludeChildNotes: query.IncludeChildNotes,
		IncludeShelves:    query.IncludeShelves,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch directory via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, directoryReplyFromProto(directory))
}

// GetDirectories godoc
// @Summary List directories
// @Description Fetch directories via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param parent_id query string false "Parent directory ID"
// @Param limit query int false "Maximum results to return"
// @Param offset query int false "Pagination offset"
// @Param include_parents query bool false "Include parent directory IDs in each response"
// @Param include_child_dirs query bool false "Include child directory IDs in each response"
// @Param include_child_notes query bool false "Include child note IDs in each response"
// @Param include_shelves query bool false "Include shelf IDs the directory sits on in each response"
// @Success 200 {object} []DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories [get]
func (dc *DirectoryController) GetDirectories(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetDirectoriesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	stream, err := (*dc.DirectoryService).GetDirectories(c, &proto.GetDirectoriesRequest{
		UserId:            user.ID,
		ParentId:          query.ParentId,
		Limit:             query.Limit,
		Offset:            query.Offset,
		IncludeParents:    query.IncludeParents,
		IncludeChildDirs:  query.IncludeChildDirs,
		IncludeChildNotes: query.IncludeChildNotes,
		IncludeShelves:    query.IncludeShelves,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch directories via gRPC service: %w", err))
		return
	}

	directories := make([]DirectoryReply, 0)
	for {
		directory, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream directories via gRPC service: %w", err))
			return
		}

		directories = append(directories, directoryReplyFromProto(directory))
	}

	c.JSON(http.StatusOK, directories)
}

// GetNotesOfDirectory godoc
// @Summary List notes in a directory
// @Description Fetch notes belonging to a directory via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param id path string true "Directory ID"
// @Param limit query int false "Maximum results to return (default 20)"
// @Param offset query int false "Pagination offset (default 0)"
// @Success 200 {object} NotesReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories/{id}/notes [get]
func (dc *DirectoryController) GetNotesOfDirectory(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Params.ByName("id")
	if id == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing directory ID"))
		return
	}

	var query GetNotesOfDirectoryQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	limit := defaultLimitForDirectoryNotes
	if query.Limit != nil {
		limit = *query.Limit
	}

	offset := defaultOffsetForDirectoryNotes
	if query.Offset != nil {
		offset = *query.Offset
	}

	reply, err := (*dc.DirectoryService).GetNotesOfDirectory(c, &proto.GetNotesOfDirectoryRequest{
		DirectoryId: id,
		Limit:       limit,
		Offset:      offset,
		UserId:      user.ID,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch directory notes via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, NotesReplyFromProto(reply))
}

// CreateDirectory godoc
// @Summary Create directory
// @Description Creates a directory via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param payload body CreateDirectoryBody true "Create directory request"
// @Success 200 {object} DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories [post]
func (dc *DirectoryController) CreateDirectory(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateDirectoryBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	directory, err := (*dc.DirectoryService).CreateDirectory(c, &proto.CreateDirectoryRequest{
		Name:        body.Name,
		DisplayName: body.DisplayName,
		Description: body.Description,
		ImageUrl:    body.ImageUrl,
		ParentIds:   body.ParentIds,
		ShelfIds:    body.ShelfIds,
		UserId:      user.ID,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to create directory via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, directoryReplyFromProto(directory))
}

// PatchDirectory godoc
// @Summary Update directory
// @Description Updates an existing directory via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param payload body PatchDirectoryBody true "Update directory request"
// @Success 200 {object} DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories [patch]
func (dc *DirectoryController) PatchDirectory(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body PatchDirectoryBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	// Build the gRPC request. Repeated fields are wrapped in the oneof
	// only when the JSON body actually provided the key -- even an empty
	// array is forwarded as "set to empty", while omission means "leave
	// unchanged".
	alterReq := &proto.AlterDirectoryRequest{
		Id:          body.Id,
		Name:        body.Name,
		DisplayName: body.DisplayName,
		Description: body.Description,
		ImageUrl:    body.ImageUrl,
		UserId:      user.ID,
	}
	if body.ParentIds != nil {
		alterReq.ParentIdsChange = &proto.AlterDirectoryRequest_ParentIds{
			ParentIds: &proto.IdsOrUndefined{Ids: body.ParentIds},
		}
	}
	if body.ShelfIds != nil {
		alterReq.ShelfIdsChange = &proto.AlterDirectoryRequest_ShelfIds{
			ShelfIds: &proto.IdsOrUndefined{Ids: body.ShelfIds},
		}
	}
	directory, err := (*dc.DirectoryService).PatchDirectory(c, alterReq)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to patch directory via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, directoryReplyFromProto(directory))
}

// DeleteDirectory godoc
// @Summary Delete directory
// @Description Deletes an existing directory via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param id path string true "Directory ID"
// @Success 200 {object} DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories/{id} [delete]
func (dc *DirectoryController) DeleteDirectory(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Params.ByName("id")
	if id == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing directory ID"))
		return
	}

	directory, err := (*dc.DirectoryService).DeleteDirectory(c, &proto.DeleteDirectoryRequest{Id: id, UserId: user.ID})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to delete directory via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, directoryReplyFromProto(directory))
}
