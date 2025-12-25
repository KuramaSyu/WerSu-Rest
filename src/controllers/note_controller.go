package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

// UserController handles user routes
type NoteController struct {
	NoteService *proto.NoteServiceClient
}

// swagger:response GetNoteRequest
type GetNoteRequest struct {
	ID models.Snowflake `json:"id" binding:"required" example:"42"`
}

type NoteReply struct {
	Id        int32     `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	UpdatedAt time.Time `json:"updated_at"`
	AuthorId  int32     `json:"author_id"`
}

type PostNoteRequest struct {
	Title   string `json:"title" binding:"required" example:"My Note Title"`
	Content string `json:"content" binding:"required" example:"This is the content of my note."`
}

// NoteReplyFromProto converts a protobuf Note message to a NoteReply struct.
//
// Parameters:
//   - note: A pointer to a proto.Note message to be converted
//
// Returns:
//   - NoteReply: A NoteReply struct populated with data from the proto.Note
func NoteReplyFromProto(note *proto.Note) NoteReply {
	return NoteReply{
		Id:        note.Id,
		Title:     note.Title,
		Content:   note.Content,
		UpdatedAt: note.UpdatedAt.AsTime(),
		AuthorId:  note.AuthorId,
	}
}

func NewNoteController(noteService *proto.NoteServiceClient) *NoteController {
	return &NoteController{NoteService: noteService}
}

// GetNote godoc
// @Summary Get note by ID
// @Description Fetch note via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "Note ID"
// @Success 200 {object} NoteReply
// @Failure 400 {object} map[string]string
// @Router /notes/{id} [get]
func (uc *NoteController) GetNote(c *gin.Context) {
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

// PostNote godoc
// @Summary Post a Note
// @Description Creates a new Note via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param payload body PostNoteRequest true "Note ID"
// @Success 200 {object} NoteReply
// @Failure 400 {object} map[string]string
// @Router /notes [post]
func (uc *NoteController) PostNote(c *gin.Context) {
	// get user from session
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	// parse request body
	var postNoteRequest PostNoteRequest
	if err := c.ShouldBindJSON(&postNoteRequest); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	// gRPC service call
	grpcPostNoteRequest := proto.PostNoteRequest{
		Title:    postNoteRequest.Title,
		Content:  &postNoteRequest.Content,
		AuthorId: user.ID,
	}
	note, err := (*uc.NoteService).PostNote(c, &grpcPostNoteRequest)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to post note via gRPC service: %w", err))
		return
	}

	// respond with created note
	c.JSON(http.StatusOK, NoteReplyFromProto(note))
}
