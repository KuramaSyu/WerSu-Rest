package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CalculatedStatsController wires REST routes to the gRPC
// CalculatedStatsService.
//
// The stats are precomputed per user by a daily background process on
// the gRPC backend.  Reads are cheap: the backend just returns the
// stored row.  The RPC is read-only, so there is no create/update
// surface here.
type CalculatedStatsController struct {
	CalculatedStatsService *proto.CalculatedStatsServiceClient
}

// NewCalculatedStatsController creates a controller bound to a
// CalculatedStatsService client.
func NewCalculatedStatsController(statsService *proto.CalculatedStatsServiceClient) *CalculatedStatsController {
	return &CalculatedStatsController{CalculatedStatsService: statsService}
}

// setCalculatedStatsGRPCError maps gRPC errors to REST status codes.
func setCalculatedStatsGRPCError(c *gin.Context, err error, op string) {
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
		case codes.Unauthenticated:
			utils.SetGinError(c, http.StatusUnauthorized, fmt.Errorf("%s: %w", op, err))
			return
		}
	}
	utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}

// CalculatedStatsReply is the REST representation of a user's
// precomputed stats row.
//
// CalculatedAt is nil when the backend returns an unset or zero
// timestamp (for example when the row has not been recomputed yet).
type CalculatedStatsReply struct {
	UserId        string     `json:"user_id" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	TotalChars    int64      `json:"total_chars" example:"12345"`
	TotalNotes    int64      `json:"total_notes" example:"42"`
	TotalChapters int64      `json:"total_chapters" example:"7"`
	TotalBooks    int64      `json:"total_books" example:"2"`
	CalculatedAt  *time.Time `json:"calculated_at,omitempty"`
}

// calculatedStatsReplyFromProto converts a gRPC CalculatedStats into the
// REST response type.
func calculatedStatsReplyFromProto(stats *proto.CalculatedStats) CalculatedStatsReply {
	reply := CalculatedStatsReply{
		UserId:        stats.GetUserId(),
		TotalChars:    stats.GetTotalChars(),
		TotalNotes:    stats.GetTotalNotes(),
		TotalChapters: stats.GetTotalChapters(),
		TotalBooks:    stats.GetTotalBooks(),
	}

	if ts := stats.GetCalculatedAt(); ts != nil && ts.IsValid() {
		calculatedAt := ts.AsTime()
		if !calculatedAt.IsZero() {
			reply.CalculatedAt = &calculatedAt
		}
	}

	return reply
}

// GetCalculatedStats godoc
// @Summary Get calculated stats for the caller
// @Description Returns the precomputed stats row for the authenticated
// @Description user.  The row is refreshed by the backend's daily
// @Description background process, so values may lag behind recent edits.
// @Tags stats
// @Accept json
// @Produce json
// @Success 200 {object} CalculatedStatsReply
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /stats [get]
func (sc *CalculatedStatsController) GetCalculatedStats(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	resp, err := (*sc.CalculatedStatsService).GetCalculatedStats(c, &proto.GetCalculatedStatsRequest{
		UserId: user.ID,
	})
	if err != nil {
		setCalculatedStatsGRPCError(c, err, "fetch calculated stats")
		return
	}

	c.JSON(http.StatusOK, calculatedStatsReplyFromProto(resp.GetStats()))
}

// GetCalculatedStatsForUser godoc
// @Summary Get calculated stats for a user
// @Description Returns the precomputed stats row for another user.
// @Description Reading another user's stats requires page-administrator
// @Description access on the gRPC backend.
// @Tags stats
// @Accept json
// @Produce json
// @Param user_id path string true "Target user ID"
// @Success 200 {object} CalculatedStatsReply
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /stats/{user_id} [get]
func (sc *CalculatedStatsController) GetCalculatedStatsForUser(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	targetUserId, code, err := utils.GetIdFromURL(c, "user_id")
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("invalid target user ID: %w", err))
		return
	}

	resp, err := (*sc.CalculatedStatsService).GetCalculatedStats(c, &proto.GetCalculatedStatsRequest{
		UserId:       user.ID,
		TargetUserId: &targetUserId,
	})
	if err != nil {
		setCalculatedStatsGRPCError(c, err, "fetch calculated stats")
		return
	}

	c.JSON(http.StatusOK, calculatedStatsReplyFromProto(resp.GetStats()))
}
