package controllers

import (
	"fmt"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

type AttachmentLinkController struct {
	AttachmentService *proto.AttachmentServiceClient
}

func NewAttachmentLinkController(
	attachmentService *proto.AttachmentServiceClient,
) *AttachmentLinkController {
	return &AttachmentLinkController{
		AttachmentService: attachmentService,
	}
}

type AttachmentLinkBody struct {
	AttachmentKey string `json:"attachment_key" binding:"required"`
	NoteId        string `json:"note_id" binding:"required"`
}

// @Summary Link attachment to note
// @Tags attachment-links
// @Accept json
// @Param payload body AttachmentLinkBody true "Link payload"
// @Success 204
// @Router /attachment-links [post]
func (alc *AttachmentLinkController) PostAttachmentLink(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body AttachmentLinkBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	_, err = (*alc.AttachmentService).PostAttachmentLink(
		c,
		&proto.PostAttachmentLinkRequest{
			AttachmentKey: body.AttachmentKey,
			NoteId:        body.NoteId,
			UserId:        user.ID,
		},
	)

	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// @Summary Unlink attachment from note
// @Tags attachment-links
// @Accept json
// @Param payload body AttachmentLinkBody true "Unlink payload"
// @Success 204
// @Router /attachment-links [delete]
func (alc *AttachmentLinkController) DeleteAttachmentLink(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body AttachmentLinkBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	_, err = (*alc.AttachmentService).DeleteAttachmentLink(
		c,
		&proto.DeleteAttachmentLinkRequest{
			AttachmentKey: body.AttachmentKey,
			NoteId:        body.NoteId,
			UserId:        user.ID,
		},
	)

	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.Status(http.StatusNoContent)
}
