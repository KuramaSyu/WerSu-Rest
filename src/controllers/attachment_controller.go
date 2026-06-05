package controllers

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/gin-gonic/gin"
)

type AttachmentController struct {
	AttachmentService *proto.AttachmentServiceClient
	authClient        *authzed.Client
	ImgproxyAddress   *string
}

func NewAttachmentController(
	attachmentService *proto.AttachmentServiceClient,
	authClient *authzed.Client,
	imgproxyAddress *string,
) *AttachmentController {
	return &AttachmentController{
		AttachmentService: attachmentService,
		authClient:        authClient,
		ImgproxyAddress:   imgproxyAddress,
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

// parameters to retrieve an image
type GetAttachmentRequest struct {
	Key    string  `form:"key" binding:"required"`
	Width  *int    `form:"width"` // *int is used, that nil is an option for not provided
	Height *int    `from:"height"`
	Format *string `form:"format"`
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
// @Accept multiplart/form-data
// @Produce json
// @Param file formData file true "Attachment"
// @Success 200 {object} AttachmentMetadataReply
// @Router /attachments [post]
func (ac *AttachmentController) PostAttachment(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	fileReader, err := file.Open()
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}
	defer fileReader.Close()

	fileContent, err := io.ReadAll(fileReader)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	contentType := http.DetectContentType(fileContent)

	attachment, err := (*ac.AttachmentService).PostAttachment(
		c,
		&proto.PostAttachmentRequest{
			Filename:    file.Filename,
			Filepath:    "",
			ContentType: contentType,
			Content:     fileContent,
			UserId:      user.ID,
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
	user, code, err := UserFromSession(c)
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
			Key:    key,
			UserId: user.ID,
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

// @Summary Get attachment
// @Tags attachments
// @Produce image/jpeg,image/png,image/webp
// @Param key query string true "Attachment key"
// @Param width query int false "Resize width"
// @Param height query int false "Resize height"
// @Param format query string false "Output format (jpeg,png,webp)"
// @Success 200 {file} binary
// @Router /attachments [get]
func (ac *AttachmentController) GetImage(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var params GetAttachmentRequest
	if err := c.ShouldBindQuery(&params); err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}
	params.Key, err = url.QueryUnescape(params.Key)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid attachment key: %w", err))
		return
	}

	// check if user has permission to view this attachment
	hasPermission, err := HasPermission(ac.authClient, "attachment", params.Key, "view", "user", user.ID)
	if err != nil {
		log.Printf("Error while fetching permission on attachment %s: %s", params.Key, err.Error())
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("Error while fetching permission: %s", err.Error()))
		return
	}
	if !hasPermission {
		log.Printf("User %s does not have permission to view attachment %s", user.ID, params.Key)
		SetGinError(c, http.StatusForbidden, fmt.Errorf("user does not have permission to view this attachment"))
		return
	}

	url := buildImgproxyURL(ac.ImgproxyAddress, &params.Key, params.Width, params.Height, params.Format)
	log.Printf("Make ImgProxy request to %s", url)

	// attachment, err := (*ac.AttachmentService).GetAttachment(
	// 	c,
	// 	&proto.GetAttachmentRequest{
	// 		Key:    params.Key,
	// 		UserId: user.ID,
	// 	},
	// )
	resp, err := http.Get(url)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	defer resp.Body.Close()

	// copy header
	for k, values := range resp.Header {
		for _, v := range values {
			c.Writer.Header().Add(k, v)
		}
	}

	// copy status code
	c.Status(resp.StatusCode)

	// copy image content to response body
	_, err = io.Copy(c.Writer, resp.Body)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

}

// @Summary Get attachment metadata
// @Tags attachments
// @Produce json
// @Param key path string true "Attachment key"
// @Success 200 {object} AttachmentMetadataReply
// @Router /attachments/{key}/metadata [get]
func (ac *AttachmentController) GetAttachmentMetadata(c *gin.Context) {
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	key := c.Param("key")

	metadata, err := (*ac.AttachmentService).GetAttachmentMetadata(
		c,
		&proto.GetAttachmentMetadataRequest{
			Key:    key,
			UserId: user.ID,
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
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	key := c.Param("key")

	response, err := (*ac.AttachmentService).DeleteAttachment(
		c,
		&proto.DeleteAttachmentRequest{
			Key:    key,
			UserId: user.ID,
		},
	)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, response)
}

// build imgproxy url with given parameters
// @param attachment the attachment to build url for
// @param width the width to resize to, or nil for auto width (hence height is required)
// @param height the height to resize to, or nil for auto height (hence width is required)
// @param format the output format (jpeg, png, webp), or nil for original format
// @returns the imgproxy url
func buildImgproxyURL(
	address *string,
	attachment *string,
	width *int,
	height *int,
	format *string,
) string {
	var baseURL = *address + "/insecure/"
	var resizePart string
	if width != nil {
		// width is provided, height is auto
		resizePart += fmt.Sprintf("rs:fit:%d:0:0,", *width)
	}
	if height != nil {
		// height is provided, width is auto
		resizePart += fmt.Sprintf("rs:fit:0:%d:0,", *height)
	}
	if format != nil {
		// format is provided, convert to it
		resizePart += fmt.Sprintf("f:%s,", *format)
	}
	formatPart := "webp"
	if format != nil {
		formatPart = *format
	}
	s3Part := fmt.Sprintf("/plain/s3://%s", *attachment)
	return baseURL + resizePart + formatPart + s3Part
}

// Helper function to call SpiceDB with format resource:id#permission@subjectType:subjectId
func HasPermission(client *authzed.Client, resourceType, resourceID, permission, subjectType, subjectID string) (bool, error) {
	log.Printf("resourceType=%q resourceID=%q", resourceType, resourceID)
	resp, err := client.CheckPermission(
		context.Background(),
		&v1.CheckPermissionRequest{
			Resource: &v1.ObjectReference{
				ObjectType: resourceType,
				ObjectId:   resourceID,
			},
			Permission: permission,
			Subject: &v1.SubjectReference{
				Object: &v1.ObjectReference{
					ObjectType: subjectType,
					ObjectId:   subjectID,
				},
			},
		},
	)
	if err != nil {
		return false, err
	}
	return resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}
