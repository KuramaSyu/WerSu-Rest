package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-gonic/gin"
)

// UserController handles user routes
type NoteController struct {
	NoteService *proto.NoteServiceClient
}

// swagger:response GetNoteRequest
type GetNoteRequest struct {
	ID string `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
}

type NoteReply struct {
	Id          string                        `json:"id"`
	Title       string                        `json:"title"`
	Content     string                        `json:"content"`
	UpdatedAt   time.Time                     `json:"updated_at"`
	AuthorId    string                        `json:"author_id"`
	Permissions []PermissionRelationshipReply `json:"permissions"`
}

type PermissionSubjectReply struct {
	ObjectType string `json:"object_type"`
	ObjectId   string `json:"object_id"`
}

type PermissionResourceReply struct {
	ObjectType string `json:"object_type"`
	ObjectId   string `json:"object_id"`
}

type PermissionRelationshipReply struct {
	Relation string                   `json:"relation"`
	Subject  *PermissionSubjectReply  `json:"subject,omitempty"`
	Resource *PermissionResourceReply `json:"resource,omitempty"`
}

func PermissionRelationshipReplyFromProto(relationship *proto.PermissionRelationship) PermissionRelationshipReply {
	permissionReply := PermissionRelationshipReply{
		Relation: relationship.GetRelation(),
	}

	if relationship.GetSubject() != nil {
		permissionReply.Subject = &PermissionSubjectReply{
			ObjectType: relationship.GetSubject().GetObjectType(),
			ObjectId:   relationship.GetSubject().GetObjectId(),
		}
	}

	if relationship.GetResource() != nil {
		permissionReply.Resource = &PermissionResourceReply{
			ObjectType: relationship.GetResource().GetObjectType().String(),
			ObjectId:   relationship.GetResource().GetObjectId(),
		}
	}

	return permissionReply
}

type PostNoteRequest struct {
	Title   string `json:"title" binding:"required" example:"My Note Title"`
	Content string `json:"content" binding:"required" example:"This is the content of my note."`
}

type PatchNoteRequest struct {
	Id      string `json:"id" binding:"required" example:"0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"`
	Title   string `json:"title" binding:"omitempty" example:"Updated Note Title"`
	Content string `json:"content" binding:"omitempty" example:"This is the updated content of my note."`
}

// NoteReplyFromProto converts a protobuf Note message to a NoteReply struct.
//
// Parameters:
//   - note: A pointer to a proto.Note message to be converted
//
// Returns:
//   - NoteReply: A NoteReply struct populated with data from the proto.Note
func NoteReplyFromProto(note *proto.Note) NoteReply {
	permissions := make([]PermissionRelationshipReply, 0, len(note.GetPermissions()))
	for _, permission := range note.GetPermissions() {
		permissions = append(permissions, PermissionRelationshipReplyFromProto(permission))
	}

	return NoteReply{
		Id:          note.Id,
		Title:       note.Title,
		Content:     note.Content,
		UpdatedAt:   note.UpdatedAt.AsTime(),
		AuthorId:    note.AuthorId,
		Permissions: permissions,
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
// @Param id path string true "Note ID (UUIDv7)"
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

	// read path UUID
	id := c.Params.ByName("id")
	if id == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing note ID"))
		return
	}

	// gRPC service
	note, err := (*uc.NoteService).GetNote(
		c, &proto.GetNoteRequest{Id: id, UserId: user.ID},
	)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to fetch note via gRPC service: %w", err))
		return
	}
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

// PatchNote godoc
// @Summary Update a note
// @Description Updates an existing note via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param payload body PatchNoteRequest true "Update Note Request"
// @Success 200 {object} NoteReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /notes [patch]
func (uc *NoteController) PatchNote(c *gin.Context) {
	// get user from session
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	// parse request body
	var patchNoteRequest PatchNoteRequest
	if err := c.ShouldBindJSON(&patchNoteRequest); err != nil {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	// gRPC service call
	grpcAlterNoteRequest := proto.AlterNoteRequest{
		Id:       patchNoteRequest.Id,
		Title:    &patchNoteRequest.Title,
		Content:  &patchNoteRequest.Content,
		AuthorId: &user.ID,
	}
	note, err := (*uc.NoteService).PatchNote(c, &grpcAlterNoteRequest)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to patch note via gRPC service: %w", err))
		return
	}

	// respond with created note
	c.JSON(http.StatusOK, NoteReplyFromProto(note))
}

// DeleteNote godoc
// @Summary Delete a note
// @Description Deletes an existing note via gRPC service
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "Note ID (UUIDv7)"
// @Success 200 {object} NoteReply
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /notes/{id} [delete]
func (uc *NoteController) DeleteNote(c *gin.Context) {
	// get user from session
	user, code, err := UserFromSession(c)
	if err != nil {
		SetGinError(c, code, fmt.Errorf("not logged in: %w", err))
		return
	}

	// parse path UUID
	id := c.Params.ByName("id")
	if id == "" {
		SetGinError(c, http.StatusBadRequest, fmt.Errorf("missing note ID"))
		return
	}

	// gRPC service call
	grpcDeleteNoteRequest := proto.DeleteNoteRequest{
		Id:       id,
		AuthorId: user.ID,
	}
	note, err := (*uc.NoteService).DeleteNote(c, &grpcDeleteNoteRequest)
	if err != nil {
		SetGinError(c, http.StatusInternalServerError, fmt.Errorf("failed to delete note via gRPC service: %w", err))
		return
	}

	// respond with created note
	c.JSON(http.StatusOK, NoteReplyFromProto(note))
}
