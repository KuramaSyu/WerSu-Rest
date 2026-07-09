package controllers

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ActivityController exposes REST endpoints backed by the
// ActivityStatisticsService gRPC service.
type ActivityController struct {
	ActivityService *proto.ActivityStatisticsServiceClient
}

// NewActivityController creates a controller for the activity-statistics gRPC
// service.
func NewActivityController(activityService *proto.ActivityStatisticsServiceClient) *ActivityController {
	return &ActivityController{ActivityService: activityService}
}

// Mode selects which gRPC method the controller invokes. Defaults to
// `ActivityModeHistory`.
type ActivityMode string

const (
	// ActivityModeHistory streams the raw activity log.
	ActivityModeHistory ActivityMode = "history"
	// ActivityModeMostUsed streams aggregated note scores.
	ActivityModeMostUsed ActivityMode = "most_used"
)

// ActivityReply is the REST representation of a single row from the activity
// log. Timestamp fields are rendered as RFC3339 strings so JSON clients don't
// need to deal with protobuf timestamp encoding.
// if the activity entry references a note, the `metadata_json` field contains
// `note_title` and `note_content`
type ActivityReply struct {
	Id           string    `json:"id"`
	ActorId      string    `json:"actor_id"`
	AccessedAs   string    `json:"accessed_as" enums:"ACCESSED_AS_UNSPECIFIED,ACCESSED_AS_USER,ACCESSED_AS_SYSTEM"`
	Action       string    `json:"action"`
	NoteId       string    `json:"note_id"`
	DirectoryId  string    `json:"directory_id"`
	RoleId       string    `json:"role_id"`
	At           time.Time `json:"at"`
	MetadataJson string    `json:"metadata_json"`
}

// ActivityScoreReply is the REST representation of an aggregated note score.
// `title` and `stripped_content` mirror the `ActivityScore` fields returned
// by the gRPC service and are omitted when empty.
type ActivityScoreReply struct {
	NoteId          string  `json:"note_id"`
	Score           float64 `json:"score"`
	Title           string  `json:"title,omitempty"`
	StrippedContent string  `json:"stripped_content,omitempty"`
}

// GetActivityHistoryQuery binds the query string for `GET /history`.
//
// Optional fields use pointers so omitted values are not filtered on by the
// gRPC service. The `mode` field toggles between raw history and aggregated
// most-used scores. Repeated values (`actions`) are read separately via
// `QueryArray` because gin's default struct-tag binding does not handle
// repeated query keys.
type GetActivityHistoryQuery struct {
	NoteId       string `form:"note_id"`
	DirectoryId  string `form:"directory_id"`
	ActorId      string `form:"actor_id"`
	RoleId       string `form:"role_id"`
	AccessedAs   string `form:"accessed_as" enums:"ACCESSED_AS_UNSPECIFIED,ACCESSED_AS_USER,ACCESSED_AS_SYSTEM"`
	Days         *int32 `form:"days"`
	Limit        *int32 `form:"limit"`
	Offset       *int32 `form:"offset"`
	UniquePerDay *bool  `form:"unique_per_day"`

	Mode      ActivityMode `form:"mode" enums:"history,most_used"`
	Algorithm string       `form:"algorithm" enums:"MOST_USED_ALGORITHM_UNSPECIFIED,MOST_USED_ALGORITHM_COUNT,MOST_USED_ALGORITHM_LOG_COUNT"`
}

// activityReplyFromProto converts a gRPC Activity into the REST response type.
func activityReplyFromProto(activity *proto.Activity) ActivityReply {
	at := time.Time{}
	if activity.GetAt() != nil {
		at = activity.GetAt().AsTime()
	}

	return ActivityReply{
		Id:           activity.GetId(),
		ActorId:      activity.GetActorId(),
		AccessedAs:   activity.GetAccessedAs().String(),
		Action:       activity.GetAction(),
		NoteId:       activity.GetNoteId(),
		DirectoryId:  activity.GetDirectoryId(),
		RoleId:       activity.GetRoleId(),
		At:           at,
		MetadataJson: activity.GetMetadataJson(),
	}
}

// activityScoreReplyFromProto converts a gRPC ActivityScore into the REST
// response type.
func activityScoreReplyFromProto(score *proto.ActivityScore) ActivityScoreReply {
	return ActivityScoreReply{
		NoteId:          score.GetNoteId(),
		Score:           score.GetScore(),
		Title:           score.GetTitle(),
		StrippedContent: score.GetStrippedContent(),
	}
}

// parseAccessedAs converts a REST `accessed_as` value into the protobuf
// AccessedAs enum. Empty input is treated as UNSPECIFIED (== "no filter"),
// matching the contract of ActivityFilter.
func parseAccessedAs(value string) (proto.AccessedAs, error) {
	if value == "" {
		return proto.AccessedAs_ACCESSED_AS_UNSPECIFIED, nil
	}
	enumValue, ok := proto.AccessedAs_value[value]
	if !ok {
		return proto.AccessedAs_ACCESSED_AS_UNSPECIFIED,
			fmt.Errorf("invalid accessed_as %q, expected one of ACCESSED_AS_UNSPECIFIED, ACCESSED_AS_USER, ACCESSED_AS_SYSTEM", value)
	}
	return proto.AccessedAs(enumValue), nil
}

// parseMostUsedAlgorithm converts a REST `algorithm` value into the protobuf
// MostUsedAlgorithm enum. Empty input defaults to COUNT, matching the gRPC
// service's documented default.
func parseMostUsedAlgorithm(value string) (proto.MostUsedAlgorithm, error) {
	if value == "" {
		return proto.MostUsedAlgorithm_MOST_USED_ALGORITHM_COUNT, nil
	}
	enumValue, ok := proto.MostUsedAlgorithm_value[value]
	if !ok {
		return proto.MostUsedAlgorithm_MOST_USED_ALGORITHM_UNSPECIFIED,
			fmt.Errorf("invalid algorithm %q, expected one of MOST_USED_ALGORITHM_UNSPECIFIED, MOST_USED_ALGORITHM_COUNT, MOST_USED_ALGORITHM_LOG_COUNT", value)
	}
	return proto.MostUsedAlgorithm(enumValue), nil
}

// activityFilterFromQuery maps the REST query into a protobuf ActivityFilter.
// Empty optional fields are passed as zero values; the gRPC service treats
// zero-valued strings / enums as "do not filter on this column".
func activityFilterFromQuery(query GetActivityHistoryQuery, actions []string) (*proto.ActivityFilter, error) {
	accessedAs, err := parseAccessedAs(query.AccessedAs)
	if err != nil {
		return nil, err
	}

	return &proto.ActivityFilter{
		NoteId:       query.NoteId,
		DirectoryId:  query.DirectoryId,
		ActorId:      query.ActorId,
		RoleId:       query.RoleId,
		AccessedAs:   accessedAs,
		Actions:      actions,
		Days:         query.Days,
		Limit:        query.Limit,
		Offset:       query.Offset,
		UniquePerDay: query.UniquePerDay,
	}, nil
}

// GetActivityHistory godoc
// @Summary Stream activity history (or most-used scores)
// @Description Streams the activity log for everything the requesting user is
// @Description allowed to view. Use `mode=most_used` to stream aggregated note
// @Description scores instead; the `algorithm` query parameter then selects the
// @Description scoring function (count or log_count).
// @Description
// @Description For entries that reference a note (`note_id` is non-empty), the
// @Description response embeds `note_title` and `note_content` into the JSON
// @Description document carried in `metadata_json`, so a single request can be
// @Description used to render history without further per-note lookups.
// @Tags history
// @Accept json
// @Produce json
// @Param note_id query string false "Filter by note ID"
// @Param directory_id query string false "Filter by directory ID"
// @Param actor_id query string false "Filter by actor user ID"
// @Param role_id query string false "Filter by role ID"
// @Param accessed_as query string false "Filter by access mode" Enums(ACCESSED_AS_USER,ACCESSED_AS_SYSTEM)
// @Param actions query []string false "Filter by one or more actions"
// @Param days query int false "Limit to events from the last N days"
// @Param limit query int false "Maximum results to return"
// @Param offset query int false "Pagination offset"
// @Param unique_per_day query bool false "Collapse repeats to one per (actor, day) before scoring"
// @Param mode query string false "history (default) or most_used" Enums(history,most_used)
// @Param algorithm query string false "Scoring algorithm for mode=most_used" Enums(MOST_USED_ALGORITHM_COUNT,MOST_USED_ALGORITHM_LOG_COUNT)
// @Success 200 {object} []ActivityReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /history [get]
func (ac *ActivityController) GetActivityHistory(c *gin.Context) {
	user, code, err := UserFromContext(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetActivityHistoryQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	mode := query.Mode
	if mode == "" {
		mode = ActivityModeHistory
	}

	// `actions` is a repeated query parameter; read it separately because the
	// struct-tag binder does not support repeated values.
	actions := c.QueryArray("actions")

	filter, err := activityFilterFromQuery(query, actions)
	if err != nil {
		SetGinError(c, http.StatusBadRequest, err)
		return
	}

	switch mode {
	case ActivityModeHistory:
		entries, err := ac.streamHistory(c, user.ID, filter)
		if err != nil {
			setActivityGRPCError(c, err, "fetch activity history")
			return
		}
		c.JSON(http.StatusOK, entries)
	case ActivityModeMostUsed:
		algorithm, err := parseMostUsedAlgorithm(query.Algorithm)
		if err != nil {
			SetGinError(c, http.StatusBadRequest, err)
			return
		}
		scores, err := ac.streamMostUsed(c, user.ID, filter, algorithm, query.Limit)
		if err != nil {
			setActivityGRPCError(c, err, "fetch most-used activity")
			return
		}
		c.JSON(http.StatusOK, scores)
	default:
		SetGinError(c, http.StatusBadRequest,
			fmt.Errorf("invalid mode %q, expected one of history, most_used", string(mode)))
	}
}

// streamHistory opens a GetActivityHistory stream and collects every entry into
// a slice. Errors from the gRPC stream itself are treated as EOF so partial
// responses are still returned to the client.
func (ac *ActivityController) streamHistory(c *gin.Context, userID string, filter *proto.ActivityFilter) ([]ActivityReply, error) {
	stream, err := (*ac.ActivityService).GetActivityHistory(c, &proto.GetActivityHistoryRequest{
		UserId: userID,
		Filter: filter,
	})
	if err != nil {
		return nil, err
	}

	entries := make([]ActivityReply, 0)
	for {
		activity, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, activityReplyFromProto(activity))
	}

	return entries, nil
}

// streamMostUsed opens a GetMostUsedActivity stream and collects every score
// into a slice. Errors from the gRPC stream itself are treated as EOF.
func (ac *ActivityController) streamMostUsed(c *gin.Context, userID string, filter *proto.ActivityFilter, algorithm proto.MostUsedAlgorithm, limit *int32) ([]ActivityScoreReply, error) {
	stream, err := (*ac.ActivityService).GetMostUsedActivity(c, &proto.GetMostUsedActivityRequest{
		UserId:    userID,
		Filter:    filter,
		Algorithm: algorithm,
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}

	scores := make([]ActivityScoreReply, 0)
	for {
		score, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		scores = append(scores, activityScoreReplyFromProto(score))
	}

	return scores, nil
}

// setActivityGRPCError maps a gRPC error from the activity service to a REST
// response. PermissionDenied becomes 403; everything else becomes 500 (and is
// subject to the transport-level 503 upgrade applied by SetGinError).
func setActivityGRPCError(c *gin.Context, err error, op string) {
	if status.Code(err) == codes.PermissionDenied {
		SetGinError(c, http.StatusForbidden, fmt.Errorf("%s: %w", op, err))
		return
	}
	SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}
