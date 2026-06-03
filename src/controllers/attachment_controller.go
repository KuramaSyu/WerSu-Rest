package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

type AttachmentController struct {
	AttachmentService *proto.AttachmentServiceClient
}

func NewAttachmentController(
	attachmentService *proto.AttachmentServiceClient,
) *AttachmentController {
	return &AttachmentController{
		AttachmentService: attachmentService,
	}
}

type AttachmentMetadataReply struct {
	Key         string    `json:"key"`
	Filename    string    `json:"filename"`
	Filepath    string    `json:"filepath"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Sha256      string    `json:"sha256"`
}

type PostAttachmentBody struct {
	Filename    string `json:"filename" binding:"required"`
	Filepath    string `json:"filepath" binding:"required"`
	ContentType string `json:"content_type" binding:"required"`
	Content     []byte `json:"content" binding:"required"`
}

func attachmentMetadataReplyFromProto(
	metadata *proto.AttachmentMetadata,
) AttachmentMetadataReply {
	createdAt := time.Time{}
	if metadata.GetCreatedAt() != nil {
		createdAt = metadata.GetCreatedAt().AsTime()
	}

	updatedAt := time.Time{}
	if metadata.GetUpdatedAt() != nil {
		updatedAt = metadata.GetUpdatedAt().AsTime()
	}

	return AttachmentMetadataReply{
		Key:         metadata.GetKey(),
		Filename:    metadata.GetFilename(),
		Filepath:    metadata.GetFilepath(),
		ContentType: metadata.GetContentType(),
		Size:        metadata.GetSize(),
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		Sha256:      metadata.GetSha256(),
	}
}

// @Summary Create attachment
// @Tags attachments
// @Accept json
// @Produce json
// @Param payload body PostAttachmentBody true "Attachment payload"
// @Success 200 {object} AttachmentMetadataReply
// @Router /attachments [post]
func (ac *AttachmentController) PostAttachment(c *gin.Context) {
	_, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body PostAttachmentBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	attachment, err := (*ac.AttachmentService).PostAttachment(
		c,
		&proto.PostAttachmentRequest{
			Filename:    body.Filename,
			Filepath:    body.Filepath,
			ContentType: body.ContentType,
			Content:     body.Content,
		},
	)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.JSON(
		http.StatusOK,
		attachmentMetadataReplyFromProto(attachment.GetMetadata()),
	)
}

// @Summary Get attachment
// @Tags attachments
// @Produce application/octet-stream
// @Param key path string true "Attachment key"
// @Success 200 {file} binary
// @Router /attachments/{key} [get]
func (ac *AttachmentController) GetAttachment(c *gin.Context) {
	_, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	key := c.Param("key")
	if key == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing attachment key"))
		return
	}

	attachment, err := (*ac.AttachmentService).GetAttachment(
		c,
		&proto.GetAttachmentRequest{
			Key: key,
		},
	)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	metadata := attachment.GetMetadata()

	c.Header(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, metadata.GetFilename()),
	)

	c.Data(
		http.StatusOK,
		metadata.GetContentType(),
		attachment.GetContent(),
	)
}

// @Summary Get attachment metadata
// @Tags attachments
// @Produce json
// @Param key path string true "Attachment key"
// @Success 200 {object} AttachmentMetadataReply
// @Router /attachments/{key}/metadata [get]
func (ac *AttachmentController) GetAttachmentMetadata(c *gin.Context) {
	_, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	key := c.Param("key")

	metadata, err := (*ac.AttachmentService).GetAttachmentMetadata(
		c,
		&proto.GetAttachmentMetadataRequest{
			Key: key,
		},
	)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.JSON(
		http.StatusOK,
		attachmentMetadataReplyFromProto(metadata),
	)
}

// @Summary Delete attachment
// @Tags attachments
// @Produce json
// @Param key path string true "Attachment key"
// @Success 200 {object} proto.DeleteAttachmentResponse
// @Router /attachments/{key} [delete]
func (ac *AttachmentController) DeleteAttachment(c *gin.Context) {
	_, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	key := c.Param("key")

	response, err := (*ac.AttachmentService).DeleteAttachment(
		c,
		&proto.DeleteAttachmentRequest{
			Key: key,
		},
	)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, response)
}
