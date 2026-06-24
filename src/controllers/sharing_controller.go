package controllers

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SharingController handles REST routes for note shares.
//
// The REST layer intentionally stays simple: optional JSON/query fields are
// represented with plain pointers, and any omitted or null value is treated as
// "not supplied". The protobuf wrappers remain an implementation detail of the
// gRPC boundary.
type SharingController struct {
	SharingService *proto.SharingServiceClient
}

// NewSharingController creates a controller for share-related routes.
func NewSharingController(sharingService *proto.SharingServiceClient) *SharingController {
	return &SharingController{SharingService: sharingService}
}

// NoteShareReply is the REST representation of a share returned to clients.
//
// Pointer fields are omitted from JSON when the gRPC object does not provide a
// value. This keeps the REST payload compact and avoids exposing protobuf-only
// wrapper types.
type NoteShareReply struct {
	Id          string     `json:"id"`
	Description *string    `json:"description,omitempty"`
	NoteId      string     `json:"note_id"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	OnlineSince *time.Time `json:"online_since,omitempty"`
	OnlineUntil *time.Time `json:"online_until,omitempty"`
}

// GetSharesQuery contains the optional query parameters used to filter shares.
//
// Nil means the client did not supply that filter. If a parameter is omitted or
// explicitly null in the request, it is treated the same way: not supplied.
type GetSharesQuery struct {
	NoteId      *string `form:"note_id"`
	CreatedBy   *string `form:"created_by"`
	OnlineSince *string `form:"online_since"`
	OnlineUntil *string `form:"online_until"`
}

// CreateShareBody represents the JSON body for creating a share.
//
// Optional fields use pointers so omitted values remain nil. That keeps the
// REST API straightforward while still allowing the controller to decide which
// protobuf wrapper fields should be populated.
type CreateShareBody struct {
	Description *string    `json:"description,omitempty" example:"Shared with the engineering team"`
	NoteId      string     `json:"note_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	OnlineSince *time.Time `json:"online_since,omitempty" example:"2026-06-21T12:00:00Z"`
	OnlineUntil *time.Time `json:"online_until,omitempty" example:"2026-06-22T12:00:00Z"`
}

// UpdateShareBody represents the JSON body for updating a share.
//
// The REST layer treats nil as "not supplied". The gRPC service still receives
// only the values that were actually provided by the caller.
type UpdateShareBody struct {
	Id          string     `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Description *string    `json:"description,omitempty" example:"Updated share description"`
	NoteId      string     `json:"note_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4ca"`
	OnlineSince *time.Time `json:"online_since,omitempty" example:"2026-06-21T12:00:00Z"`
	OnlineUntil *time.Time `json:"online_until,omitempty" example:"2026-06-22T12:00:00Z"`
}

// DeleteSharesBody is the JSON body for deleting multiple shares in one call.
type DeleteSharesBody struct {
	ShareIds []string `json:"share_ids" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// unwraps a nullable timestamp which returns the time if given, otherwise nil
func unwrapNullableDatetime(nullable *proto.NullableTimestamp) *time.Time {
	if nullable == nil {
		return nil
	}
	if value, ok := nullable.Kind.(*proto.NullableTimestamp_Value); ok {
		t := value.Value.AsTime()
		return &t
	}
	return nil
}

// creates a nullable timestamp proto value from a time pointer
func nullableTimestampFromTime(t *time.Time) *proto.NullableTimestamp {
	if t == nil {
		return nil
	}
	return &proto.NullableTimestamp{
		Kind: &proto.NullableTimestamp_Value{Value: timestamppb.New(*t)},
	}
}

// noteShareReplyFromProto converts a gRPC NoteShare into the REST response type.
//
// The conversion exists so that the API surface stays JSON-friendly and does not
// leak protobuf wrappers or timestamp helpers to clients.
func noteShareReplyFromProto(share *proto.NoteShare) NoteShareReply {
	var description *string
	if share.GetDescription() != nil {
		if value, ok := share.GetDescription().Kind.(*proto.NullableString_Value); ok {
			description = &value.Value
		}
	}

	onlineSince := unwrapNullableDatetime(share.GetOnlineSince())

	onlineUntil := unwrapNullableDatetime(share.GetOnlineUntil())

	createdAt := time.Time{}
	if share.GetCreatedAt() != nil {
		createdAt = share.GetCreatedAt().AsTime()
	}

	return NoteShareReply{
		Id:          share.GetId(),
		Description: description,
		NoteId:      share.GetNoteId(),
		CreatedAt:   createdAt,
		CreatedBy:   share.GetCreatedBy(),
		OnlineSince: onlineSince,
		OnlineUntil: onlineUntil,
	}
}

// stringToNullableProto converts an optional REST string into the protobuf
// NullableString wrapper used by the gRPC service.
//
// Nil means the field was not supplied and should be omitted from the request.
func stringToNullableProto(value *string) *proto.NullableString {
	if value == nil {
		return nil
	}

	return &proto.NullableString{
		Kind: &proto.NullableString_Value{Value: *value},
	}
}

// timeToNullableProto converts an optional REST timestamp into the protobuf
// NullableTimestamp wrapper used by the gRPC service.
//
// Nil means the field was not supplied and should be omitted from the request.
func timeToNullableProto(value *time.Time) *proto.NullableTimestamp {
	if value == nil {
		return nil
	}

	return &proto.NullableTimestamp{
		Kind: &proto.NullableTimestamp_Value{Value: timestamppb.New(*value)},
	}
}

// parseOptionalRFC3339 parses an optional RFC3339 timestamp string.
//
// Query parameters arrive as strings, so the controller converts them explicitly
// instead of relying on implicit binding behavior. Nil means the parameter was
// not supplied.
func parseOptionalRFC3339(value *string) (*timestamppb.Timestamp, error) {
	if value == nil || *value == "" {
		return nil, nil
	}

	parsed, err := time.Parse(time.RFC3339, *value)
	if err != nil {
		return nil, err
	}

	return timestamppb.New(parsed), nil
}

// shareFilterFromQuery converts REST query parameters into a protobuf share filter.
//
// This helper exists so the handler stays focused on HTTP concerns while all
// query-to-proto mapping is kept in one place.
func shareFilterFromQuery(query GetSharesQuery) (*proto.ShareFilter, error) {
	filter := &proto.ShareFilter{
		NoteId:    query.NoteId,
		CreatedBy: query.CreatedBy,
	}

	if ts, err := parseOptionalRFC3339(query.OnlineSince); err != nil {
		return nil, fmt.Errorf("invalid online_since: %w", err)
	} else if ts != nil {
		filter.OnlineSince = &proto.NullableTimestamp{
			Kind: &proto.NullableTimestamp_Value{Value: ts},
		}
	}

	if ts, err := parseOptionalRFC3339(query.OnlineUntil); err != nil {
		return nil, fmt.Errorf("invalid online_until: %w", err)
	} else if ts != nil {
		filter.OnlineUntil = &proto.NullableTimestamp{
			Kind: &proto.NullableTimestamp_Value{Value: ts},
		}
	}

	return filter, nil
}

// createShareProtoFromBody converts a REST create request into the protobuf
// request payload expected by the gRPC service.
func createShareProtoFromBody(body CreateShareBody, userID string) *proto.NoteShare {
	return &proto.NoteShare{
		Id:          "",
		Description: stringToNullableProto(body.Description),
		NoteId:      body.NoteId,
		CreatedAt:   nil,
		CreatedBy:   userID,
		OnlineSince: timeToNullableProto(body.OnlineSince),
		OnlineUntil: timeToNullableProto(body.OnlineUntil),
	}
}

// updateShareProtoFromBody converts a REST update request into the protobuf
// payload expected by the gRPC service.
func updateShareProtoFromBody(body UpdateShareBody, userID string) *proto.NoteShare {
	return &proto.NoteShare{
		Id:          body.Id,
		Description: stringToNullableProto(body.Description),
		NoteId:      body.NoteId,
		CreatedAt:   nil,
		CreatedBy:   userID,
		OnlineSince: timeToNullableProto(body.OnlineSince),
		OnlineUntil: timeToNullableProto(body.OnlineUntil),
	}
}

// GetShareById godoc
// @Summary Get share by ID
// @Description Fetch a single share by ID via gRPC service
// @Tags shares
// @Accept json
// @Produce json
// @Param id path string true "Share ID"
// @Success 200 {object} NoteShareReply
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shares/{id} [get]
func (sc *SharingController) GetShareById(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Param("id")
	if id == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing share ID"))
		return
	}

	stream, err := (*sc.SharingService).GetSharesById(c, &proto.GetSharesByIdRequest{
		UserId:   user.ID,
		ShareIds: []string{id},
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch share via gRPC service: %w", err))
		return
	}

	share, err := stream.Recv()
	if err == io.EOF {
		SetGinError(c, http.StatusNotFound, fmt.Errorf("share not found"))
		return
	}
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream share via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, noteShareReplyFromProto(share))
}

// GetSharesById godoc
// @Summary Get shares by IDs
// @Description Fetch shares by exact IDs via gRPC service
// @Tags shares
// @Accept json
// @Produce json
// @Param share_ids query []string true "Share IDs"
// @Success 200 {object} []NoteShareReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shares/by-id [get]
func (sc *SharingController) GetSharesById(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	shareIDs := c.QueryArray("share_ids")
	if len(shareIDs) == 0 {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing share IDs"))
		return
	}

	stream, err := (*sc.SharingService).GetSharesById(c, &proto.GetSharesByIdRequest{
		UserId:   user.ID,
		ShareIds: shareIDs,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch shares via gRPC service: %w", err))
		return
	}

	shares := make([]NoteShareReply, 0, len(shareIDs))
	for {
		share, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream shares via gRPC service: %w", err))
			return
		}

		shares = append(shares, noteShareReplyFromProto(share))
	}

	c.JSON(http.StatusOK, shares)
}

// GetShares godoc
// @Summary List shares
// @Description Fetch shares via gRPC service
// @Tags shares
// @Accept json
// @Produce json
// @Param note_id query string false "Note ID"
// @Param created_by query string false "Creator user ID"
// @Param online_since query string false "RFC3339 timestamp"
// @Param online_until query string false "RFC3339 timestamp"
// @Param access_as query string false "Access role"
// @Success 200 {object} []NoteShareReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shares [get]
func (sc *SharingController) GetShares(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetSharesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	filter, err := shareFilterFromQuery(query)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	stream, err := (*sc.SharingService).GetShares(c, &proto.GetSharesRequest{
		UserId: user.ID,
		Filter: filter,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch shares via gRPC service: %w", err))
		return
	}

	shares := make([]NoteShareReply, 0)
	for {
		share, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to stream shares via gRPC service: %w", err))
			return
		}

		shares = append(shares, noteShareReplyFromProto(share))
	}

	c.JSON(http.StatusOK, shares)
}

// CreateShare godoc
// @Summary Create share
// @Description Creates a share via gRPC service
// @Tags shares
// @Accept json
// @Produce json
// @Param payload body CreateShareBody true "Create share request"
// @Success 200 {object} NoteShareReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shares [post]
func (sc *SharingController) CreateShare(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateShareBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	share := createShareProtoFromBody(body, user.ID)

	created, err := (*sc.SharingService).CreateShare(c, &proto.CreateShareRequest{
		UserId: user.ID,
		Description: &proto.NullableString{
			Kind: &proto.NullableString_Value{Value: *body.Description},
		},
		NoteId:      body.NoteId,
		OnlineSince: nullableTimestampFromTime(body.OnlineSince),
		OnlineUntil: nullableTimestampFromTime(body.OnlineUntil),
		Permission:  share.Permission,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to create share via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, noteShareReplyFromProto(created))
}

// UpdateShare godoc
// @Summary Update share
// @Description Updates an existing share via gRPC service
// @Tags shares
// @Accept json
// @Produce json
// @Param payload body UpdateShareBody true "Update share request"
// @Success 200 {object} NoteShareReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shares [patch]
func (sc *SharingController) UpdateShare(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body UpdateShareBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	share := updateShareProtoFromBody(body, user.ID)

	updated, err := (*sc.SharingService).UpdateShare(c, &proto.UpdateShareRequest{
		UserId: user.ID,
		Share:  share,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to update share via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, noteShareReplyFromProto(updated))
}

// DeleteShares godoc
// @Summary Delete shares
// @Description Deletes shares via gRPC service
// @Tags shares
// @Accept json
// @Produce json
// @Param payload body DeleteSharesBody true "Delete shares request"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /shares [delete]
func (sc *SharingController) DeleteShares(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DeleteSharesBody
	if err := c.ShouldBindJSON(&body); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if len(body.ShareIds) == 0 {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing share IDs"))
		return
	}

	_, err = (*sc.SharingService).DeleteShares(c, &proto.DeleteSharesRequest{
		UserId:   user.ID,
		ShareIds: body.ShareIds,
	})
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to delete shares via gRPC service: %w", err))
		return
	}

	c.Status(http.StatusNoContent)
}
