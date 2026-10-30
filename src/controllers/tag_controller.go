package controllers

import (
	"fmt"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TagController wires REST routes to the gRPC TagService.
//
// Tags form a flat, global taxonomy shared across notes and
// directories.  They carry no SpiceDB relations themselves; the
// visibility of tagged notes/directories stays rooted in their own
// relations.  Every write path forwards the calling user id so the
// gRPC backend can run its permission checks.
type TagController struct {
	TagService *proto.TagServiceClient
}

// NewTagController creates a controller bound to a TagService client.
func NewTagController(tagService *proto.TagServiceClient) *TagController {
	return &TagController{TagService: tagService}
}

// setTagGRPCError maps gRPC errors to REST status codes.
func setTagGRPCError(c *gin.Context, err error, op string) {
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
		case codes.AlreadyExists:
			utils.SetGinError(c, http.StatusConflict, fmt.Errorf("%s: %w", op, err))
			return
		}
	}
	utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}

// TagReply is the REST representation of a tag.
type TagReply struct {
	Id          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// DeleteTagReply is the response shape for a DeleteTag call.
//
// `Deleted` is true when a tag row was removed and false when no row
// matched the supplied id.
type DeleteTagReply struct {
	Deleted bool `json:"deleted"`
}

// CreateTagBody is the JSON body for creating a tag.
type CreateTagBody struct {
	Slug        string `json:"slug" binding:"required" example:"engineering"`
	DisplayName string `json:"display_name" binding:"required" example:"Engineering"`
}

// UpdateTagBody is the JSON body for updating a tag.
//
// All optional fields are pointers so we can distinguish "field
// omitted" (leave unchanged) from "field set to empty string"
// (explicit clear).  The proto uses `optional` fields for the same
// reason.
type UpdateTagBody struct {
	Slug        *string `json:"slug,omitempty" example:"engineering"`
	DisplayName *string `json:"display_name,omitempty" example:"Engineering"`
}

// tagReplyFromProto converts a gRPC MinimalTag into the REST shape.
func tagReplyFromProto(tag *proto.MinimalTag) TagReply {
	return TagReply{
		Id:          tag.GetId(),
		Slug:        tag.GetSlug(),
		DisplayName: tag.GetDisplayName(),
	}
}

// CreateTag godoc
// @Summary Create tag
// @Description Creates a tag via the gRPC service.  Slugs must be unique.
// @Tags tags
// @Accept json
// @Produce json
// @Param payload body CreateTagBody true "Create tag request"
// @Success 200 {object} TagReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /tags [post]
func (tc *TagController) CreateTag(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateTagBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*tc.TagService).CreateTag(c, &proto.CreateTagRequest{
		UserId:      user.ID,
		Slug:        body.Slug,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		setTagGRPCError(c, err, "create tag")
		return
	}

	c.JSON(http.StatusOK, tagReplyFromProto(resp.GetTag()))
}

// GetTag godoc
// @Summary Get tag by ID
// @Description Fetches a single tag by ID via the gRPC service.
// @Tags tags
// @Accept json
// @Produce json
// @Param id path string true "Tag ID"
// @Success 200 {object} TagReply
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /tags/{id} [get]
func (tc *TagController) GetTag(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id, code, err := utils.GetIdFromURL(c, "id")
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("missing tag ID: %w", err))
		return
	}

	resp, err := (*tc.TagService).GetTag(c, &proto.GetTagRequest{
		UserId: user.ID,
		Id:     id,
	})
	if err != nil {
		setTagGRPCError(c, err, "fetch tag")
		return
	}

	c.JSON(http.StatusOK, tagReplyFromProto(resp.GetTag()))
}

// ListTags godoc
// @Summary List tags
// @Description Lists every tag via the gRPC service.
// @Tags tags
// @Accept json
// @Produce json
// @Success 200 {object} []TagReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /tags [get]
func (tc *TagController) ListTags(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	resp, err := (*tc.TagService).ListTags(c, &proto.ListTagsRequest{
		UserId: user.ID,
	})
	if err != nil {
		setTagGRPCError(c, err, "list tags")
		return
	}

	tags := make([]TagReply, 0, len(resp.GetTags()))
	for _, tag := range resp.GetTags() {
		tags = append(tags, tagReplyFromProto(tag))
	}
	c.JSON(http.StatusOK, tags)
}

// UpdateTag godoc
// @Summary Update tag
// @Description Partially updates a tag via the gRPC service.  Omitted
// @Description fields are left unchanged.
// @Tags tags
// @Accept json
// @Produce json
// @Param id path string true "Tag ID"
// @Param payload body UpdateTagBody true "Update tag request"
// @Success 200 {object} TagReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /tags/{id} [patch]
func (tc *TagController) UpdateTag(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id, code, err := utils.GetIdFromURL(c, "id")
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("missing tag ID: %w", err))
		return
	}

	var body UpdateTagBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	resp, err := (*tc.TagService).UpdateTag(c, &proto.UpdateTagRequest{
		UserId:      user.ID,
		Id:          id,
		Slug:        body.Slug,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		setTagGRPCError(c, err, "update tag")
		return
	}

	c.JSON(http.StatusOK, tagReplyFromProto(resp.GetTag()))
}

// DeleteTag godoc
// @Summary Delete tag
// @Description Deletes a tag via the gRPC service.  The response reports
// @Description whether a row was actually removed.
// @Tags tags
// @Accept json
// @Produce json
// @Param id path string true "Tag ID"
// @Success 200 {object} DeleteTagReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /tags/{id} [delete]
func (tc *TagController) DeleteTag(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id, code, err := utils.GetIdFromURL(c, "id")
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("missing tag ID: %w", err))
		return
	}

	resp, err := (*tc.TagService).DeleteTag(c, &proto.DeleteTagRequest{
		UserId: user.ID,
		Id:     id,
	})
	if err != nil {
		setTagGRPCError(c, err, "delete tag")
		return
	}

	c.JSON(http.StatusOK, DeleteTagReply{Deleted: resp.GetDeleted()})
}
