package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
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
}

type MinimalNote struct {
	Id              int32  `json:"id"`
	Title           string `json:"title"`
	AuthorId        int32  `json:"author_id"`
	UpdatedAt       string `json:"updated_at"` // ISO 8601 format
	StrippedContent string `json:"stripped_content"`
}

// ConvertProtoMinimalNoteToRest converts a proto.MinimalNote to REST MinimalNote
func ConvertProtoMinimalNoteToRest(protoNote *proto.MinimalNote) MinimalNote {
	updatedAt := ""
	if protoNote.UpdatedAt != nil {
		updatedAt = protoNote.UpdatedAt.AsTime().Format(time.RFC3339)
	}

	return MinimalNote{
		Id:              protoNote.Id,
		Title:           protoNote.Title,
		AuthorId:        protoNote.AuthorId,
		UpdatedAt:       updatedAt,
		StrippedContent: protoNote.StrippedContent,
	}
}

// GetNote godoc
// @Summary Get notes by search criteria
// @Description Search notes via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param search_type query string true "Search algorithm" Enums(context, keyword, typo_tolerant, latest)
// @Param query query string true "Search query"
// @Param limit query int true "Maximum results to return"
// @Param offset query int true "Pagination offset"
// @Success 200 {object} []MinimalNote
// @Failure 400 {object} map[string]string
// @Router /notes/search [get]
func (uc *SearchNotesController) GetNotes(c *gin.Context) {
	// get user from session
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	// read query parameters
	var getSearchNotesRequest GetSearchNotesRequest
	if err := c.ShouldBindQuery(&getSearchNotesRequest); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid query parameters: %w", err))
		return
	}

	// call gRPC service
	grpcSearchNotesRequest := proto.GetSearchNotesRequest{
		SearchType: MapSearchTypeToProto(getSearchNotesRequest.SearchType),
		Query:      getSearchNotesRequest.Query,
		Limit:      getSearchNotesRequest.Limit,
		Offset:     getSearchNotesRequest.Offset,
		UserId:     user.ID,
	}
	stream, err := (*uc.NoteService).SearchNotes(c, &grpcSearchNotesRequest)
	// collect all notes from stream
	var notes []MinimalNote = []MinimalNote{}
	for {
		note, err := stream.Recv()
		if err != nil {
			break
		}
		notes = append(notes, ConvertProtoMinimalNoteToRest(note))
	}

	// respond
	c.JSON(http.StatusOK, notes)
}
