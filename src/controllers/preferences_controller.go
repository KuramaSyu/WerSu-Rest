package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PreferencesController wires REST routes to the gRPC PreferencesService.
type PreferencesController struct {
	PreferencesService *proto.PreferencesServiceClient
}

// NewPreferencesController creates a controller bound to a
// PreferencesService client.
func NewPreferencesController(preferencesService *proto.PreferencesServiceClient) *PreferencesController {
	return &PreferencesController{PreferencesService: preferencesService}
}

// setPreferencesGRPCError maps gRPC errors to REST status codes.
func setPreferencesGRPCError(c *gin.Context, err error, op string) {
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
		}
	}
	utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to %s via gRPC service: %w", op, err))
}

// REST scope labels accepted on the wire.
const (
	PreferenceScopeUser  = "user"
	PreferenceScopeShelf = "shelf"
	PreferenceScopeRole  = "role"
)

// preferenceScopeFromString maps a lowercase REST scope to the proto enum.
// Unknown values produce an error so the caller can 400 the request.
func preferenceScopeFromString(s string) (proto.PreferenceScope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case PreferenceScopeUser:
		return proto.PreferenceScope_PREFERENCE_SCOPE_USER, nil
	case PreferenceScopeShelf:
		return proto.PreferenceScope_PREFERENCE_SCOPE_SHELF, nil
	case PreferenceScopeRole:
		return proto.PreferenceScope_PREFERENCE_SCOPE_ROLE, nil
	default:
		return proto.PreferenceScope_PREFERENCE_SCOPE_UNSPECIFIED, fmt.Errorf(
			"invalid scope: %q (expected one of %q, %q, %q)",
			s, PreferenceScopeUser, PreferenceScopeShelf, PreferenceScopeRole,
		)
	}
}

// validatePreferencesJSON rejects strings that don't parse to a JSON object.
func validatePreferencesJSON(s string) error {
	if s == "" {
		return fmt.Errorf("preferences_json must not be empty")
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return fmt.Errorf("preferences_json is not valid JSON: %w", err)
	}
	if _, ok := v.(map[string]any); !ok {
		return fmt.Errorf("preferences_json must encode a JSON object, got %T", v)
	}
	return nil
}

// GetPreferencesQuery filters the GET.
type GetPreferencesQuery struct {
	Scope    string `form:"scope" binding:"required,oneof=user shelf role" example:"user"`
	TargetId string `form:"target_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PreferencesJsonBody is the JSON body for POST (replace) and PATCH (merge).
type PreferencesJsonBody struct {
	Scope           string `json:"scope" binding:"required,oneof=user shelf role" example:"user"`
	TargetId        string `json:"target_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	PreferencesJson string `json:"preferences_json" binding:"required" example:"{\"theme\":\"dark\",\"language\":\"de\"}"`
}

// DeletePreferencesBody is the JSON body for DELETE.
type DeletePreferencesBody struct {
	Scope    string `json:"scope" binding:"required,oneof=user shelf role" example:"user"`
	TargetId string `json:"target_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// PreferencesReply wraps the JSON blob returned by GET / POST / PATCH.
type PreferencesReply struct {
	PreferencesJson string `json:"preferences_json" example:"{\"theme\":\"dark\",\"language\":\"de\"}"`
}

// DeletePreferencesReply reports whether the row was actually removed.
type DeletePreferencesReply struct {
	Success bool `json:"success" example:"true"`
}

// preferencesReplyFromProto wraps a proto response into the REST shape.
// Treats nil or empty JSON as {}.
func preferencesReplyFromProto(resp *proto.GetPreferencesResponse) PreferencesReply {
	if resp == nil || resp.GetPreferencesJson() == "" {
		return PreferencesReply{PreferencesJson: "{}"}
	}
	return PreferencesReply{PreferencesJson: resp.GetPreferencesJson()}
}

// GetPreferences godoc
// @Summary Read preferences
// @Description Returns the stored JSON blob for the (scope, target_id) pair. Returns {} when no row exists.
// @Tags preferences
// @Accept json
// @Produce json
// @Param scope query string true "Scope: user | shelf | role"
// @Param target_id query string true "Target entity id"
// @Success 200 {object} PreferencesReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /preferences [get]
func (pc *PreferencesController) GetPreferences(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetPreferencesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	scope, err := preferenceScopeFromString(query.Scope)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	resp, err := (*pc.PreferencesService).GetPreferences(c, &proto.GetPreferencesRequest{
		Scope:    scope,
		TargetId: query.TargetId,
		UserId:   user.ID,
	})
	if err != nil {
		setPreferencesGRPCError(c, err, "fetch preferences")
		return
	}

	c.JSON(http.StatusOK, preferencesReplyFromProto(resp))
}

// PostPreferences godoc
// @Summary Replace preferences
// @Description Replaces the stored JSON blob wholesale with the payload.
// @Tags preferences
// @Accept json
// @Produce json
// @Param payload body PreferencesJsonBody true "Preferences replacement"
// @Success 200 {object} PreferencesReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /preferences [post]
func (pc *PreferencesController) PostPreferences(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body PreferencesJsonBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}
	if err := validatePreferencesJSON(body.PreferencesJson); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	scope, err := preferenceScopeFromString(body.Scope)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	resp, err := (*pc.PreferencesService).PostPreferences(c, &proto.PostPreferencesRequest{
		Scope:           scope,
		TargetId:        body.TargetId,
		PreferencesJson: body.PreferencesJson,
		UserId:          user.ID,
	})
	if err != nil {
		setPreferencesGRPCError(c, err, "post preferences")
		return
	}

	c.JSON(http.StatusOK, preferencesReplyFromProto(resp))
}

// PatchPreferences godoc
// @Summary Merge preferences
// @Description Shallow-merges the payload into the stored blob. Top-level keys overwrite the same keys in storage; nested objects and lists are replaced wholesale.
// @Tags preferences
// @Accept json
// @Produce json
// @Param payload body PreferencesJsonBody true "Preferences merge payload"
// @Success 200 {object} PreferencesReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /preferences [patch]
func (pc *PreferencesController) PatchPreferences(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body PreferencesJsonBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}
	if err := validatePreferencesJSON(body.PreferencesJson); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	scope, err := preferenceScopeFromString(body.Scope)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	resp, err := (*pc.PreferencesService).PatchPreferences(c, &proto.PatchPreferencesRequest{
		Scope:           scope,
		TargetId:        body.TargetId,
		PreferencesJson: body.PreferencesJson,
		UserId:          user.ID,
	})
	if err != nil {
		setPreferencesGRPCError(c, err, "patch preferences")
		return
	}

	c.JSON(http.StatusOK, preferencesReplyFromProto(resp))
}

// DeletePreferences godoc
// @Summary Delete preferences
// @Description Drops the stored blob. Idempotent; success is true iff a row was actually removed.
// @Tags preferences
// @Accept json
// @Produce json
// @Param payload body DeletePreferencesBody true "Target to drop"
// @Success 200 {object} DeletePreferencesReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /preferences [delete]
func (pc *PreferencesController) DeletePreferences(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body DeletePreferencesBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	scope, err := preferenceScopeFromString(body.Scope)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}

	resp, err := (*pc.PreferencesService).DeletePreferences(c, &proto.DeletePreferencesRequest{
		Scope:    scope,
		TargetId: body.TargetId,
		UserId:   user.ID,
	})
	if err != nil {
		setPreferencesGRPCError(c, err, "delete preferences")
		return
	}

	c.JSON(http.StatusOK, DeletePreferencesReply{Success: resp.GetSuccess()})
}
