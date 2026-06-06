package controllers

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/authzed/authzed-go/v1"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	. "github.com/KuramaSyu/WerSu-Rest/src/utils"
)

type AttachmentController struct {
	AttachmentService *proto.AttachmentServiceClient
	authClient        *authzed.Client
	ImgproxyAddress   *string
	S3Client          *s3.Client
	S3DefaultBucket   string
}

func NewAttachmentController(
	attachmentService *proto.AttachmentServiceClient,
	authClient *authzed.Client,
	imgproxyAddress *string,
	s3Client *s3.Client,
	s3DefaultBucket string,
) *AttachmentController {
	return &AttachmentController{
		AttachmentService: attachmentService,
		authClient:        authClient,
		ImgproxyAddress:   imgproxyAddress,
		S3Client:          s3Client,
		S3DefaultBucket:   s3DefaultBucket,
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

// parameters to retrieve metadata of an attachment
type GetAttachmentMetadataRequest struct {
	Key string `form:"key" binding:"required"`
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
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("Failed to open uploaded file: %s", err.Error()))
		return
	}
	defer fileReader.Close()

	key, err := ac.PutToS3(fileReader)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("Failed to PUT file: %s", err.Error()))
		return
	}

	fileContent, err := io.ReadAll(fileReader)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("Failed to read file content: %s", err.Error()))
		return
	}
	contentType := http.DetectContentType(fileContent)

	attachment, err := (*ac.AttachmentService).PostAttachment(
		c,
		&proto.PostAttachmentRequest{
			Filename:    file.Filename,
			Filepath:    key,
			ContentType: contentType,
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

	// get metadata first - this also does permision check
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

	// get object directly from S3 out of performance reasons (S3 is faster then gRPC)
	ctx := context.Background()
	object, err := ac.S3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &ac.S3DefaultBucket,
		Key:    &key,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("Failed to get file from S3: %s", err.Error()))
		return
	}

	// read content of file
	defer object.Body.Close()
	content, err := io.ReadAll(object.Body)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("Failed to read file content: %s", err.Error()))
		return
	}

	c.Header(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, metadata.GetFilename()),
	)

	c.Data(
		http.StatusOK,
		metadata.GetContentType(),
		content,
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
	} else if !hasPermission {
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

	var params GetAttachmentMetadataRequest
	if err := c.ShouldBindQuery(&params); err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}
	params.Key, err = url.QueryUnescape(params.Key)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid attachment key: %w", err))
		return
	} else if params.Key == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("parameter key can't be empty"))
		return
	}

	metadata, err := (*ac.AttachmentService).GetAttachmentMetadata(
		c,
		&proto.GetAttachmentMetadataRequest{
			Key:    params.Key,
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

// puts an attachment to S3 and returns the S3 key (excluding bucket)
func (ac *AttachmentController) PutToS3(file io.Reader) (string, error) {
	// generate uuidv7 key for attachment
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("attachments/%s", id.String())
	ctx := context.Background()
	_, err = ac.S3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &ac.S3DefaultBucket,
		Key:    &key,
		Body:   file,
	})
	if err != nil {
		return "", err
	}
	return key, nil
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
	bucket := "garage"
	// eleminate trailing / of attachment
	*attachment = strings.TrimPrefix(*attachment, "/")
	s3Part := fmt.Sprintf("/plain/s3://%s/%s", bucket, *attachment)

	return baseURL + resizePart + formatPart + s3Part
}
