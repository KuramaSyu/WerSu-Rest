package controllers

import (
	"fmt"
	"net/http"
	"strconv"

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

type GetSearchNotesRequest struct {
	// the algorithm used to perform the search
	SearchType SearchType `json:"search_type" binding:"required" example:"context"`

	// the query string to search for
	Query string `json:"query" binding:"required" example:"Python programming"`

	// maximum number of results to return
	Limit  int32 `json:"limit" binding:"required" example:"10"`
	Offset int32 `json:"offset" binding:"required" example:"0"`
}

// GetNote godoc
// @Summary Get notes by search criteria
// @Description Search notes via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param payload body GetSearchNotesRequest true "Search Notes Request"
// @Success 200 {object} NoteReply[]
// @Failure 400 {object} map[string]string
// @Router /notes/search [get]
func (uc *SearchNotesController) GetNotes(c *gin.Context) {
	// get user from session
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	// read path
	id, err := strconv.Atoi(c.Params.ByName("id"))
	if err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid ID format: %w", err))
		return
	}

	// gRPC service
	note, err := (*uc.NoteService).GetNote(
		c, &proto.GetNoteRequest{Id: int32(id), UserId: user.ID},
	)
	c.JSON(http.StatusOK, NoteReplyFromProto(note))
}
