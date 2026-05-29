package controllers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOpeninaryControllerForwardsRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var upstreamMethod string
	var upstreamPath string
	var upstreamAuth string
	var upstreamBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamMethod = r.Method
		upstreamPath = r.URL.Path
		upstreamAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	router := gin.New()
	controller := NewOpeninaryController(upstream.URL, "test-api-key")
	router.Any("/api/openinary", controller.Handle)
	router.Any("/api/openinary/*path", controller.Handle)

	server := httptest.NewServer(router)
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/openinary/upload", strings.NewReader("file-bytes"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	request.Header.Set("Content-Type", "multipart/form-data; boundary=test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}
	if upstreamMethod != http.MethodPost {
		t.Fatalf("expected method POST, got %s", upstreamMethod)
	}
	if upstreamPath != "/upload" {
		t.Fatalf("expected upstream path /upload, got %s", upstreamPath)
	}
	if upstreamAuth != "Bearer test-api-key" {
		t.Fatalf("expected auth header to be forwarded, got %q", upstreamAuth)
	}
	if upstreamBody != "file-bytes" {
		t.Fatalf("expected request body to be forwarded, got %q", upstreamBody)
	}
}
