package controllers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
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
	Name          string                        `json:"name"`
	DisplayName   string                        `json:"display_name"`
	Description   string                        `json:"description"`
	ImageUrl      string                        `json:"image_url"`
	ParentId      *string                       `json:"parent_id,omitempty"`
	Relationships []PermissionRelationshipReply `json:"relationships"`
}

type GetDirectoriesQuery struct {
	ParentId *string `form:"parent_id"`
	Limit    *int32  `form:"limit"`
	Offset   *int32  `form:"offset"`
}

type CreateDirectoryBody struct {
	Name        string  `json:"name" binding:"required" example:"engineering"`
	DisplayName *string `json:"display_name,omitempty" example:"Engineering"`
	Description *string `json:"description,omitempty" example:"Shared notes for engineering team"`
	ImageUrl    *string `json:"image_url,omitempty" example:"https://cdn.example.com/engineering.png"`
	ParentId    *string `json:"parent_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

type PatchDirectoryBody struct {
	Id          string  `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Name        *string `json:"name,omitempty" example:"engineering"`
	DisplayName *string `json:"display_name,omitempty" example:"Engineering"`
	Description *string `json:"description,omitempty" example:"Shared notes for engineering team"`
	ImageUrl    *string `json:"image_url,omitempty" example:"https://cdn.example.com/engineering.png"`
	ParentId    *string `json:"parent_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

func directoryReplyFromProto(directory *proto.Directory) DirectoryReply {
	relationships := make([]PermissionRelationshipReply, 0, len(directory.GetRelationships()))
	for _, relationship := range directory.GetRelationships() {
		relationships = append(relationships, PermissionRelationshipReplyFromProto(relationship))
	}

	var parentID *string
	if directory.ParentId != nil {
		parentID = directory.ParentId
	}

	return DirectoryReply{
		Id:            directory.GetId(),
		Name:          directory.GetName(),
		DisplayName:   directory.GetDisplayName(),
		Description:   directory.GetDescription(),
		ImageUrl:      directory.GetImageUrl(),
		ParentId:      parentID,
		Relationships: relationships,
	}
}

// GetDirectory godoc
// @Summary Get directory by ID
// @Description Fetch directory via gRPC service
// @Tags directories
// @Accept json
// @Produce json
// @Param id path string true "Directory ID"
// @Success 200 {object} DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories/{id} [get]
func (dc *DirectoryController) GetDirectory(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Params.ByName("id")
	if id == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing directory ID"))
		return
	}

	directory, err := (*dc.DirectoryService).GetDirectory(c, &proto.GetDirectoryRequest{Id: id, UserId: user.ID})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch directory via gRPC service: %w", err))
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
// @Success 200 {object} []DirectoryReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /directories [get]
func (dc *DirectoryController) GetDirectories(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetDirectoriesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	stream, err := (*dc.DirectoryService).GetDirectories(c, &proto.GetDirectoriesRequest{
		UserId:   user.ID,
		ParentId: query.ParentId,
		Limit:    query.Limit,
		Offset:   query.Offset,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch directories via gRPC service: %w", err))
		return
	}

	directories := make([]DirectoryReply, 0)
	for {
		directory, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream directories via gRPC service: %w", err))
			return
		}

		directories = append(directories, directoryReplyFromProto(directory))
	}

	c.JSON(http.StatusOK, directories)
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
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateDirectoryBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	directory, err := (*dc.DirectoryService).CreateDirectory(c, &proto.CreateDirectoryRequest{
		Name:        body.Name,
		DisplayName: body.DisplayName,
		Description: body.Description,
		ImageUrl:    body.ImageUrl,
		ParentId:    body.ParentId,
		UserId:      user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to create directory via gRPC service: %w", err))
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
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body PatchDirectoryBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	directory, err := (*dc.DirectoryService).PatchDirectory(c, &proto.AlterDirectoryRequest{
		Id:          body.Id,
		Name:        body.Name,
		DisplayName: body.DisplayName,
		Description: body.Description,
		ImageUrl:    body.ImageUrl,
		ParentId:    body.ParentId,
		UserId:      user.ID,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to patch directory via gRPC service: %w", err))
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
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Params.ByName("id")
	if id == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing directory ID"))
		return
	}

	directory, err := (*dc.DirectoryService).DeleteDirectory(c, &proto.DeleteDirectoryRequest{Id: id, UserId: user.ID})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to delete directory via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, directoryReplyFromProto(directory))
}
