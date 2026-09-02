// Package controllers -- RuleController exposes the gRPC RuleService
// over REST.
//
// Rules are conditional automation: "if X then do Y".  The proto
// shape separates the rule body (a `google.protobuf.Struct`
// condition and a typed `action_type` + `Struct` action_context)
// from the scope anchor (`attached_entity_type` / `attached_entity_id`)
// so a rule only fires for events tied to a specific directory /
// note / shelf -- global rules are not supported.
//
// All scalar fields except the id are pointers so we can distinguish
// "field omitted" (leave unchanged) from "field set to zero value"
// (explicit clear).  The proto uses `optional` fields for the same
// reason.
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
	"google.golang.org/protobuf/types/known/structpb"
)

// RuleController wires REST routes to the gRPC RuleService.
type RuleController struct {
	RuleService *proto.RuleServiceClient
}

// NewRuleController creates a controller bound to a RuleService client.
func NewRuleController(ruleService *proto.RuleServiceClient) *RuleController {
	return &RuleController{RuleService: ruleService}
}

// setRuleGRPCError maps gRPC errors to REST status codes.
func setRuleGRPCError(c *gin.Context, err error, op string) {
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

// RuleReply is the REST representation of a Rule.
//
// `Condition` and `ActionContext` round-trip as JSON objects so
// the frontend can render them generically.  See `rule.proto` for
// the set of valid `condition.type` / `action_type` strings.
type RuleReply struct {
	Id                 string         `json:"id"`
	EventType          string         `json:"event_type"`
	AttachedEntityType string         `json:"attached_entity_type"`
	AttachedEntityId   string         `json:"attached_entity_id"`
	Condition          map[string]any `json:"condition,omitempty"`
	ActionType         string         `json:"action_type"`
	ActionContext      map[string]any `json:"action_context,omitempty"`
	Enabled            bool           `json:"enabled"`
	CreatorId          string         `json:"creator_id,omitempty"`
	CreatedAt          *time.Time     `json:"created_at,omitempty"`
	UpdatedAt          *time.Time     `json:"updated_at,omitempty"`
}

// CreateRuleBody is the JSON body for creating a rule.
//
// `Condition` and `ActionContext` are arbitrary JSON objects that
// are forwarded to the gRPC service as `google.protobuf.Struct`.
type CreateRuleBody struct {
	EventType          string         `json:"event_type" binding:"required" example:"note_created"`
	AttachedEntityType string         `json:"attached_entity_type" binding:"required" example:"directory"`
	AttachedEntityId   string         `json:"attached_entity_id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Condition          map[string]any `json:"condition" binding:"required" example:"{\"type\":\"always_true\"}"`
	ActionType         string         `json:"action_type" binding:"required" example:"add_to_directory"`
	ActionContext      map[string]any `json:"action_context" binding:"required" example:"{\"directory_id\":\"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb\"}"`
	Enabled            *bool          `json:"enabled,omitempty" example:"true"`
	// CreatorId defaults to the requesting user when omitted.
	CreatorId string `json:"creator_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// UpdateRuleBody is the JSON body for updating a rule.
//
// The rule id comes from the URL path (`PATCH /rules/:id`).
// All other fields are pointers.  A pointer-to-struct maps
// to a non-empty optional; a `null` JSON value becomes a nil map
// pointer, which we forward as a missing field on the gRPC side
// ("leave unchanged").  `Condition` and `ActionContext` are
// pointers-to-maps so we can distinguish "leave alone" from
// "explicitly set to {}".
type UpdateRuleBody struct {
	EventType          *string         `json:"event_type,omitempty" example:"note_created"`
	AttachedEntityType *string         `json:"attached_entity_type,omitempty" example:"shelf"`
	AttachedEntityId   *string         `json:"attached_entity_id,omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Condition          *map[string]any `json:"condition,omitempty"`
	ActionType         *string         `json:"action_type,omitempty" example:"add_tag"`
	ActionContext      *map[string]any `json:"action_context,omitempty"`
	Enabled            *bool           `json:"enabled,omitempty" example:"false"`
}

// GetRulesQuery filters a list call.  All fields are optional.
type GetRulesQuery struct {
	EventType          string `form:"event_type" example:"note_created"`
	AttachedEntityType string `form:"attached_entity_type" example:"directory"`
	AttachedEntityId   string `form:"attached_entity_id" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	EnabledOnly        bool   `form:"enabled_only" example:"true"`
	CreatorId          string `form:"creator_id" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

// ruleReplyFromProto converts a gRPC Rule into the REST shape.
//
// `structpb.Struct` -> `map[string]any` round-trip happens through
// `struct.AsMap()` / `structpb.NewStruct(...)`.  We drop nil
// maps so the JSON output omits unset fields.
func ruleReplyFromProto(rule *proto.Rule) RuleReply {
	reply := RuleReply{
		Id:                 rule.GetId(),
		EventType:          rule.GetEventType(),
		AttachedEntityType: rule.GetAttachedEntityType(),
		AttachedEntityId:   rule.GetAttachedEntityId(),
		ActionType:         rule.GetActionType(),
		Enabled:            rule.GetEnabled(),
		CreatorId:          rule.GetCreatorId(),
	}
	if rule.GetCondition() != nil {
		reply.Condition = rule.GetCondition().AsMap()
	}
	if rule.GetActionContext() != nil {
		reply.ActionContext = rule.GetActionContext().AsMap()
	}
	if rule.GetCreatedAt() != nil {
		t := rule.GetCreatedAt().AsTime()
		reply.CreatedAt = &t
	}
	if rule.GetUpdatedAt() != nil {
		t := rule.GetUpdatedAt().AsTime()
		reply.UpdatedAt = &t
	}
	return reply
}

// structFromMap builds a `google.protobuf.Struct` from a Go map.
// Returns nil when the input is nil so callers can preserve
// "field not provided" semantics.
func structFromMap(m map[string]any) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

// CreateRule godoc
// @Summary Create rule
// @Description Creates a rule via the gRPC service.
// @Tags rules
// @Accept json
// @Produce json
// @Param payload body CreateRuleBody true "Create rule request"
// @Success 200 {object} RuleReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /rules [post]
func (rc *RuleController) CreateRule(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var body CreateRuleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	condition, err := structFromMap(body.Condition)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid condition: %w", err))
		return
	}
	actionContext, err := structFromMap(body.ActionContext)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid action_context: %w", err))
		return
	}

	resp, err := (*rc.RuleService).CreateRule(c, &proto.CreateRuleRequest{
		UserId:             user.ID,
		EventType:          body.EventType,
		AttachedEntityType: body.AttachedEntityType,
		AttachedEntityId:   body.AttachedEntityId,
		Condition:          condition,
		ActionType:         body.ActionType,
		ActionContext:      actionContext,
		Enabled:            body.Enabled,
		CreatorId:          body.CreatorId,
	})
	if err != nil {
		setRuleGRPCError(c, err, "create rule")
		return
	}

	c.JSON(http.StatusOK, ruleReplyFromProto(resp.GetRule()))
}

// GetRule godoc
// @Summary Get rule by ID
// @Description Fetches a single rule by ID via the gRPC service.
// @Tags rules
// @Accept json
// @Produce json
// @Param id path string true "Rule ID"
// @Success 200 {object} RuleReply
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /rules/{id} [get]
func (rc *RuleController) GetRule(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id := c.Param("id")
	if id == "" {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing rule ID"))
		return
	}

	resp, err := (*rc.RuleService).GetRule(c, &proto.GetRuleRequest{
		UserId: user.ID,
		Id:     id,
	})
	if err != nil {
		setRuleGRPCError(c, err, "fetch rule")
		return
	}

	c.JSON(http.StatusOK, ruleReplyFromProto(resp.GetRule()))
}

// GetRules godoc
// @Summary List rules
// @Description Lists rules matching an optional filter via the gRPC service.
// @Tags rules
// @Accept json
// @Produce json
// @Param event_type query string false "Filter by event type"
// @Param attached_entity_type query string false "Filter by attached entity type"
// @Param attached_entity_id query string false "Filter by attached entity id"
// @Param enabled_only query bool false "Only include enabled rules"
// @Param creator_id query string false "Filter by creator id"
// @Success 200 {object} []RuleReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /rules [get]
func (rc *RuleController) GetRules(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	var query GetRulesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	resp, err := (*rc.RuleService).GetRules(c, &proto.GetRulesRequest{
		UserId: user.ID,
		Filter: &proto.RuleFilter{
			EventType:          query.EventType,
			AttachedEntityType: query.AttachedEntityType,
			AttachedEntityId:   query.AttachedEntityId,
			EnabledOnly:        query.EnabledOnly,
			CreatorId:          query.CreatorId,
		},
	})
	if err != nil {
		setRuleGRPCError(c, err, "list rules")
		return
	}

	rules := make([]RuleReply, 0, len(resp.GetRules()))
	for _, rule := range resp.GetRules() {
		rules = append(rules, ruleReplyFromProto(rule))
	}

	c.JSON(http.StatusOK, rules)
}

// UpdateRule godoc
// @Summary Update rule
// @Description Updates an existing rule via the gRPC service.
// @Tags rules
// @Accept json
// @Produce json
// @Param id path string true "Rule ID"
// @Param payload body UpdateRuleBody true "Update rule request"
// @Success 200 {object} RuleReply
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /rules/{id} [patch]
func (rc *RuleController) UpdateRule(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id, code, err := utils.GetIdFromURL(c, "id")
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("missing rule ID: %w", err))
		return
	}

	var body UpdateRuleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	req := &proto.UpdateRuleRequest{
		UserId:     user.ID,
		Id:         id,
		EventType:  body.EventType,
		ActionType: body.ActionType,
		Enabled:    body.Enabled,
	}

	// Convert attached_entity pointers only when set.  A nil
	// pointer means "leave unchanged" on the wire.
	if body.AttachedEntityType != nil {
		req.AttachedEntityType = body.AttachedEntityType
	}
	if body.AttachedEntityId != nil {
		req.AttachedEntityId = body.AttachedEntityId
	}

	// Condition / ActionContext are tricky: a missing JSON key
	// must NOT clobber the stored value.  Gin's JSON binder
	// leaves pointers nil when the key is absent, so nil here
	// maps to "leave alone" on the proto side (the proto also
	// uses optional).  We never call structFromMap on nil.
	if body.Condition != nil {
		cond, err := structFromMap(*body.Condition)
		if err != nil {
			utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid condition: %w", err))
			return
		}
		req.Condition = cond
	}
	if body.ActionContext != nil {
		ac, err := structFromMap(*body.ActionContext)
		if err != nil {
			utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid action_context: %w", err))
			return
		}
		req.ActionContext = ac
	}

	resp, err := (*rc.RuleService).UpdateRule(c, req)
	if err != nil {
		setRuleGRPCError(c, err, "update rule")
		return
	}

	c.JSON(http.StatusOK, ruleReplyFromProto(resp.GetRule()))
}

// DeleteRule godoc
// @Summary Delete rule
// @Description Deletes a rule via the gRPC service.
// @Tags rules
// @Accept json
// @Produce json
// @Param id path string true "Rule ID"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /rules/{id} [delete]
func (rc *RuleController) DeleteRule(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	id, code, err := utils.GetIdFromURL(c, "id")
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("missing rule ID: %w", err))
		return
	}

	if _, err := (*rc.RuleService).DeleteRule(c, &proto.DeleteRuleRequest{
		UserId: user.ID,
		Id:     id,
	}); err != nil {
		setRuleGRPCError(c, err, "delete rule")
		return
	}

	c.Status(http.StatusNoContent)
}

// silence "io imported but not used" if the gRPC client ever drops
