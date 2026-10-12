package controllers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
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

// AttachmentLinkBody is the REST payload for POST/DELETE /attachment-links.
//
// link_to is optional and mirrors the gRPC LinkTarget enum:
//   - "" (omitted) -> UNSPECIFIED; the gRPC server treats it as NOTE.
//   - "note"       -> NOTE; note_id is required.
//   - "user"       -> USER; user_id is required.
//
// Existing clients that only send attachment_key + note_id keep working:
// link_to defaults to UNSPECIFIED and note_id is forwarded as before.
type AttachmentLinkBody struct {
	AttachmentKey string `json:"attachment_key" binding:"required"`
	LinkTo        string `json:"link_to,omitempty" binding:"omitempty,oneof=note user" enums:"note,user" example:"note"`
	NoteId        string `json:"note_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	UserId        string `json:"user_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// validateLinkBody returns the normalized link_to target ("", "note", "user")
// and a 400-worthy error if the body is missing the matching ID.
func validateLinkBody(body AttachmentLinkBody) (string, error) {
	target := strings.ToLower(strings.TrimSpace(body.LinkTo))
	switch target {
	case "", "note":
		if body.NoteId == "" {
			return "", fmt.Errorf("note_id is required when link_to is %q", body.LinkTo)
		}
	case "user":
		if body.UserId == "" {
			return "", fmt.Errorf("user_id is required when link_to is %q", body.LinkTo)
		}
	default:
		return "", fmt.Errorf("invalid link_to %q (expected \"note\" or \"user\")", body.LinkTo)
	}
	return target, nil
}

// postLinkTarget maps the REST target to the gRPC LinkTarget for Post.
// An empty target becomes UNSPECIFIED so the server applies its NOTE default.
func postLinkTarget(target string) proto.PostAttachmentLinkRequest_LinkTarget {
	switch target {
	case "note":
		return proto.PostAttachmentLinkRequest_LINK_TARGET_NOTE
	case "user":
		return proto.PostAttachmentLinkRequest_LINK_TARGET_USER
	default:
		return proto.PostAttachmentLinkRequest_LINK_TARGET_UNSPECIFIED
	}
}

// deleteLinkTarget mirrors postLinkTarget for the Delete RPC.
func deleteLinkTarget(target string) proto.DeleteAttachmentLinkRequest_LinkTarget {
	switch target {
	case "note":
		return proto.DeleteAttachmentLinkRequest_LINK_TARGET_NOTE
	case "user":
		return proto.DeleteAttachmentLinkRequest_LINK_TARGET_USER
	default:
		return proto.DeleteAttachmentLinkRequest_LINK_TARGET_UNSPECIFIED
	}
}

// @Summary Link attachment to a note (default) or user
// @Tags attachment-links
// @Accept json
// @Param payload body AttachmentLinkBody true "Link payload"
// @Success 204
// @Router /attachment-links [post]
func (alc *AttachmentLinkController) PostAttachmentLink(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body AttachmentLinkBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	target, err := validateLinkBody(body)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	_, err = (*alc.AttachmentService).PostAttachmentLink(
		c,
		&proto.PostAttachmentLinkRequest{
			AttachmentKey: body.AttachmentKey,
			NoteIdLink:    body.NoteId,
			UserIdLink:    body.UserId,
			LinkTarget:    postLinkTarget(target),
			UserId:        user.ID,
		},
	)

	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// @Summary Unlink attachment from a note (default) or user
// @Tags attachment-links
// @Accept json
// @Param payload body AttachmentLinkBody true "Unlink payload"
// @Success 204
// @Router /attachment-links [delete]
func (alc *AttachmentLinkController) DeleteAttachmentLink(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body AttachmentLinkBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	target, err := validateLinkBody(body)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	_, err = (*alc.AttachmentService).DeleteAttachmentLink(
		c,
		&proto.DeleteAttachmentLinkRequest{
			AttachmentKey: body.AttachmentKey,
			NoteId:        body.NoteId,
			UserIdLink:    body.UserId,
			LinkTarget:    deleteLinkTarget(target),
			UserId:        user.ID,
		},
	)

	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.Status(http.StatusNoContent)
}
