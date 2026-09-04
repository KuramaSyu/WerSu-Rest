package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
)

// UserController handles user routes
type SearchNotesController struct {
	NoteService *proto.NoteServiceClient
}

func NewSearchNoteController(noteService *proto.NoteServiceClient) *SearchNotesController {
	return &SearchNotesController{NoteService: noteService}
}

type SearchType string

const (
	SearchByContext      SearchType = "context"
	SearchByKeyword      SearchType = "keyword"
	SearchByTypoTolerant SearchType = "typo_tolerant"
	SearchByLatest       SearchType = "latest"
)

// maps the REST API SearchType to gRPC SearchType
func MapSearchTypeToProto(searchType SearchType) proto.GetSearchNotesRequest_SearchType {
	switch searchType {
	case SearchByContext:
		return proto.GetSearchNotesRequest_Context
	case SearchByKeyword:
		return proto.GetSearchNotesRequest_FullTextTitle
	case SearchByTypoTolerant:
		return proto.GetSearchNotesRequest_Fuzzy
	case SearchByLatest:
		return proto.GetSearchNotesRequest_NoSearch
	default:
		return proto.GetSearchNotesRequest_Context
	}
}

type GetSearchNotesRequest struct {
	// the algorithm used to perform the search
	SearchType SearchType `form:"search_type" binding:"required" example:"context"`

	// the query string to search for
	Query string `form:"query" binding:"omitempty" example:"Python programming"`

	// maximum number of results to return
	Limit  int32 `form:"limit" binding:"omitempty" example:"10"`
	Offset int32 `form:"offset" binding:"omitempty" example:"0"`

	// optional RFC3339 lower bound on note updated_at
	DateFrom *string `form:"date_from" binding:"omitempty" example:"2026-01-01T00:00:00Z"`
	// optional RFC3339 upper bound on note updated_at
	DateUntil *string `form:"date_until" binding:"omitempty" example:"2026-12-31T23:59:59Z"`

	// optional repeated id filters forwarded to proto.NoteSearchFilter
	IncludeDirectoryIds []string `form:"include_directory_ids" binding:"omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	ExcludeDirectoryIds []string `form:"exclude_directory_ids" binding:"omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	IncludeShelfIds     []string `form:"include_shelf_ids" binding:"omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	ExcludeShelfIds     []string `form:"exclude_shelf_ids" binding:"omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	IncludeTagIds       []string `form:"include_tag_ids" binding:"omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	ExcludeTagIds       []string `form:"exclude_tag_ids" binding:"omitempty" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

type MinimalNote struct {
	Id              string                        `json:"id"`
	Title           string                        `json:"title"`
	AuthorId        string                        `json:"author_id"`
	UpdatedAt       string                        `json:"updated_at"` // ISO 8601 format
	StrippedContent string                        `json:"stripped_content"`
	Permissions     []PermissionRelationshipReply `json:"permissions"`
	DirectoryIds    []string                      `json:"directory_ids,omitempty"`
	TagIds          []string                      `json:"tag_ids,omitempty"`
}

// MinimalDirectory is the REST representation of a proto.MinimalDirectory.
type MinimalDirectory struct {
	Id          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// MinimalTag is the REST representation of a proto.MinimalTag.
type MinimalTag struct {
	Id          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// NotesReply is the REST representation of a proto.NotesReply. It bundles
// the matching notes with the directories and tags referenced by them so
// the client can render a single response without follow-up calls.
type NotesReply struct {
	Notes       []MinimalNote      `json:"notes"`
	Directories []MinimalDirectory `json:"directories"`
	Tags        []MinimalTag       `json:"tags"`
}

// ConvertProtoMinimalNoteToRest converts a proto.MinimalNote to REST MinimalNote
func ConvertProtoMinimalNoteToRest(protoNote *proto.MinimalNote) MinimalNote {
	updatedAt := ""
	if protoNote.UpdatedAt != nil {
		updatedAt = protoNote.UpdatedAt.AsTime().Format(time.RFC3339)
	}

	// Convert proto permission entries to the REST response type.
	permissions := make([]PermissionRelationshipReply, 0, len(protoNote.GetPermissions()))
	for _, permission := range protoNote.GetPermissions() {
		permissions = append(permissions, PermissionRelationshipReplyFromProto(permission))
	}

	return MinimalNote{
		Id:              protoNote.Id,
		Title:           protoNote.Title,
		AuthorId:        protoNote.AuthorId,
		UpdatedAt:       updatedAt,
		StrippedContent: protoNote.StrippedContent,
		Permissions:     permissions,
		DirectoryIds:    protoNote.GetDirectoryIds(),
		TagIds:          protoNote.GetTagIds(),
	}
}

// ConvertProtoMinimalDirectoryToRest converts a proto.MinimalDirectory to REST MinimalDirectory.
func ConvertProtoMinimalDirectoryToRest(protoDirectory *proto.MinimalDirectory) MinimalDirectory {
	return MinimalDirectory{
		Id:          protoDirectory.GetId(),
		Slug:        protoDirectory.GetSlug(),
		DisplayName: protoDirectory.GetDisplayName(),
	}
}

// ConvertProtoMinimalTagToRest converts a proto.MinimalTag to REST MinimalTag.
func ConvertProtoMinimalTagToRest(protoTag *proto.MinimalTag) MinimalTag {
	return MinimalTag{
		Id:          protoTag.GetId(),
		Slug:        protoTag.GetSlug(),
		DisplayName: protoTag.GetDisplayName(),
	}
}

// NotesReplyFromProto converts a proto.NotesReply into the REST NotesReply shape.
func NotesReplyFromProto(reply *proto.NotesReply) NotesReply {
	if reply == nil {
		return NotesReply{
			Notes:       []MinimalNote{},
			Directories: []MinimalDirectory{},
			Tags:        []MinimalTag{},
		}
	}

	notes := make([]MinimalNote, 0, len(reply.GetNotes()))
	for _, note := range reply.GetNotes() {
		notes = append(notes, ConvertProtoMinimalNoteToRest(note))
	}

	directories := make([]MinimalDirectory, 0, len(reply.GetDirectories()))
	for _, directory := range reply.GetDirectories() {
		directories = append(directories, ConvertProtoMinimalDirectoryToRest(directory))
	}

	tags := make([]MinimalTag, 0, len(reply.GetTags()))
	for _, tag := range reply.GetTags() {
		tags = append(tags, ConvertProtoMinimalTagToRest(tag))
	}

	return NotesReply{
		Notes:       notes,
		Directories: directories,
		Tags:        tags,
	}
}

// GetNote godoc
// @Summary Get notes by search criteria
// @Description Search notes via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param search_type query string true "Search algorithm" Enums(context, keyword, typo_tolerant, latest)
// @Param query query string false "Search query"
// @Param limit query int false "Maximum results to return"
// @Param offset query int false "Pagination offset"
// @Param include_directory_ids query []string false "Restrict to notes in any of these directories (XOR with exclude_directory_ids)"
// @Param exclude_directory_ids query []string false "Exclude notes in any of these directories (XOR with include_directory_ids)"
// @Param include_shelf_ids query []string false "Restrict to notes on any of these shelves (XOR with exclude_shelf_ids)"
// @Param exclude_shelf_ids query []string false "Exclude notes on any of these shelves (XOR with include_shelf_ids)"
// @Param include_tag_ids query []string false "Restrict to notes tagged with any of these tags (XOR with exclude_tag_ids)"
// @Param exclude_tag_ids query []string false "Exclude notes tagged with any of these tags (XOR with include_tag_ids)"
// @Param date_from query string false "RFC3339 lower bound on note updated_at"
// @Param date_until query string false "RFC3339 upper bound on note updated_at"
// @Success 200 {object} NotesReply
// @Failure 400 {object} map[string]string
// @Router /notes/search [get]
func (uc *SearchNotesController) GetNotes(c *gin.Context) {
	// get user from session
	user, code, err := utils.UserFromContext(c)
	if err != nil {
		utils.SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	// read query parameters
	var getSearchNotesRequest GetSearchNotesRequest
	if err := c.ShouldBindQuery(&getSearchNotesRequest); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	// collect every malformed date field, then bail once.
	dateDetails := map[string]string{}
	dateFrom, err := utils.ParseOptionalTimestamp(getSearchNotesRequest.DateFrom)
	if err != nil {
		dateDetails["date_from"] = (&utils.TimestampFieldError{Field: "date_from", Value: utils.DerefString(getSearchNotesRequest.DateFrom)}).Detail()
	}
	dateUntil, err := utils.ParseOptionalTimestamp(getSearchNotesRequest.DateUntil)
	if err != nil {
		dateDetails["date_until"] = (&utils.TimestampFieldError{Field: "date_until", Value: utils.DerefString(getSearchNotesRequest.DateUntil)}).Detail()
	}
	if len(dateDetails) > 0 {
		utils.SetGinBadRequestWithDetails(c, "invalid query parameters", dateDetails)
		return
	}

	filter := &proto.NoteSearchFilter{
		IncludeDirectoryIds: getSearchNotesRequest.IncludeDirectoryIds,
		ExcludeDirectoryIds: getSearchNotesRequest.ExcludeDirectoryIds,
		IncludeShelfIds:     getSearchNotesRequest.IncludeShelfIds,
		ExcludeShelfIds:     getSearchNotesRequest.ExcludeShelfIds,
		IncludeTagIds:       getSearchNotesRequest.IncludeTagIds,
		ExcludeTagIds:       getSearchNotesRequest.ExcludeTagIds,
		DateFrom:            dateFrom,
		DateUntil:           dateUntil,
	}

	// call gRPC service
	grpcSearchNotesRequest := proto.GetSearchNotesRequest{
		SearchType: MapSearchTypeToProto(getSearchNotesRequest.SearchType),
		Query:      getSearchNotesRequest.Query,
		Limit:      getSearchNotesRequest.Limit,
		Offset:     getSearchNotesRequest.Offset,
		UserId:     user.ID,
		Filter:     filter,
	}
	reply, err := (*uc.NoteService).SearchNotes(c, &grpcSearchNotesRequest)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to search notes via gRPC service: %w", err))
		return
	}

	c.JSON(http.StatusOK, NotesReplyFromProto(reply))
}
