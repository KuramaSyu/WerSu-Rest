package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

// mockUserServiceClient captures the requests the controller sends to the
// UserService gRPC layer and returns canned responses.
type mockUserServiceClient struct {
	getUser    func(ctx context.Context, in *proto.GetUserRequest, opts ...grpc.CallOption) (*proto.User, error)
	postUser   func(ctx context.Context, in *proto.PostUserRequest, opts ...grpc.CallOption) (*proto.User, error)
	alterUser  func(ctx context.Context, in *proto.AlterUserRequest, opts ...grpc.CallOption) (*proto.User, error)
	deleteUser func(ctx context.Context, in *proto.DeleteUserRequest, opts ...grpc.CallOption) (*proto.DeleteUserResponse, error)
	searchUser func(ctx context.Context, in *proto.SearchUserRequest, opts ...grpc.CallOption) (*proto.SearchUserResponse, error)
	getUsers   func(ctx context.Context, in *proto.GetUsersRequest, opts ...grpc.CallOption) (*proto.GetUsersResponse, error)
}

func (m *mockUserServiceClient) GetUser(ctx context.Context, in *proto.GetUserRequest, opts ...grpc.CallOption) (*proto.User, error) {
	return m.getUser(ctx, in, opts...)
}
func (m *mockUserServiceClient) PostUser(ctx context.Context, in *proto.PostUserRequest, opts ...grpc.CallOption) (*proto.User, error) {
	return m.postUser(ctx, in, opts...)
}
func (m *mockUserServiceClient) AlterUser(ctx context.Context, in *proto.AlterUserRequest, opts ...grpc.CallOption) (*proto.User, error) {
	return m.alterUser(ctx, in, opts...)
}
func (m *mockUserServiceClient) DeleteUser(ctx context.Context, in *proto.DeleteUserRequest, opts ...grpc.CallOption) (*proto.DeleteUserResponse, error) {
	return m.deleteUser(ctx, in, opts...)
}
func (m *mockUserServiceClient) SearchUser(ctx context.Context, in *proto.SearchUserRequest, opts ...grpc.CallOption) (*proto.SearchUserResponse, error) {
	return m.searchUser(ctx, in, opts...)
}
func (m *mockUserServiceClient) GetUsers(ctx context.Context, in *proto.GetUsersRequest, opts ...grpc.CallOption) (*proto.GetUsersResponse, error) {
	return m.getUsers(ctx, in, opts...)
}

func setupUserRouter(client proto.UserServiceClient) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("discord_auth", store))
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("user", models.User{ID: "caller-1"})
		_ = session.Save()
		c.Next()
	})

	controller := NewUserController(&client)
	api := router.Group("/api")
	users := api.Group("/users")
	{
		users.GET("/search", controller.SearchUsers)
		users.POST("/by-ids", controller.GetUsersByIds)
	}
	return router
}

func testUser() *proto.User {
	return &proto.User{
		Id:            "user-2",
		DiscordId:     123456789,
		Username:      "kuro",
		Discriminator: "0001",
		Avatar:        "avatar-hash",
		Email:         "secret@example.com",
	}
}

func TestSearchUsers(t *testing.T) {
	var got *proto.SearchUserRequest
	client := &mockUserServiceClient{
		searchUser: func(_ context.Context, in *proto.SearchUserRequest, _ ...grpc.CallOption) (*proto.SearchUserResponse, error) {
			got = in
			return &proto.SearchUserResponse{Users: []*proto.User{testUser()}}, nil
		},
	}

	router := setupUserRouter(client)
	req := httptest.NewRequest(http.MethodGet, "/api/users/search?query=ku", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if got.GetQuery() != "ku" || got.GetUserId() != "caller-1" {
		t.Fatalf("request = %+v, want query=ku user_id=caller-1", got)
	}

	var replies []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &replies); err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0]["id"] != "user-2" || replies[0]["username"] != "kuro" {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
	if _, ok := replies[0]["email"]; ok {
		t.Fatalf("response leaked email: %s", w.Body.String())
	}
}

func TestGetUsersByIds(t *testing.T) {
	var got *proto.GetUsersRequest
	client := &mockUserServiceClient{
		getUsers: func(_ context.Context, in *proto.GetUsersRequest, _ ...grpc.CallOption) (*proto.GetUsersResponse, error) {
			got = in
			return &proto.GetUsersResponse{Users: []*proto.User{testUser()}}, nil
		},
	}

	router := setupUserRouter(client)
	body := bytes.NewBufferString(`{"ids":["user-2"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/users/by-ids", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if got.GetUserId() != "caller-1" || len(got.GetIds()) != 1 || got.GetIds()[0] != "user-2" {
		t.Fatalf("request = %+v, want user_id=caller-1 ids=[user-2]", got)
	}

	var replies []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &replies); err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0]["id"] != "user-2" {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
	if _, ok := replies[0]["email"]; ok {
		t.Fatalf("response leaked email: %s", w.Body.String())
	}
}
