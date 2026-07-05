package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// runSetGinError invokes SetGinError against a recorder so a test can read
// back the status code and JSON body it produced.
func runSetGinError(t *testing.T, statusCode int, err error) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	SetGinError(c, statusCode, err)

	var body map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	return recorder, body
}

// TestSetGinErrorUpgradesGrpcUnavailableToServiceUnavailable confirms that
// calling SetGinError with status=500 and a gRPC error that signals an
// unreachable backend (Unavailable / DeadlineExceeded / ResourceExhausted)
// results in a 503 response so REST clients can distinguish "backend down"
// from generic internal errors.
func TestSetGinErrorUpgradesGrpcUnavailableToServiceUnavailable(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
	}{
		{"Unavailable", codes.Unavailable},
		{"DeadlineExceeded", codes.DeadlineExceeded},
		{"ResourceExhausted", codes.ResourceExhausted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, _ := runSetGinError(t, http.StatusInternalServerError,
				status.Error(tc.code, "backend unreachable"))

			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d", recorder.Code)
			}
		})
	}
}

// TestSetGinErrorUpgradesWrappedGrpcUnavailable verifies that the upgrade
// still fires when the gRPC status error is wrapped via fmt.Errorf("...: %w").
// SetGinError must look through the wrapping to find the original gRPC code.
func TestSetGinErrorUpgradesWrappedGrpcUnavailable(t *testing.T) {
	wrapped := fmt.Errorf("failed to fetch directory via gRPC service: %w",
		status.Error(codes.Unavailable, "connection refused"))

	recorder, _ := runSetGinError(t, http.StatusInternalServerError, wrapped)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for wrapped Unavailable error, got %d", recorder.Code)
	}
}

// TestSetGinErrorLeavesOtherGrpcCodesAs500 ensures only the configured
// "unreachable" codes trigger the upgrade. Other gRPC codes (Internal,
// PermissionDenied, NotFound, ...) must continue to surface as 500 since
// they represent server- or permission-side issues, not transport failures.
func TestSetGinErrorLeavesOtherGrpcCodesAs500(t *testing.T) {
	cases := []codes.Code{
		codes.Internal,
		codes.PermissionDenied,
		codes.NotFound,
		codes.Unauthenticated,
	}

	for _, code := range cases {
		t.Run(code.String(), func(t *testing.T) {
			recorder, _ := runSetGinError(t, http.StatusInternalServerError,
				status.Error(code, "some grpc error"))

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500 for gRPC code %s, got %d", code, recorder.Code)
			}
		})
	}
}

// TestSetGinErrorLeavesPlainErrorAs500 ensures a plain (non-gRPC) error
// stays at 500 — only errors that carry a gRPC status code get the
// upgrade.
func TestSetGinErrorLeavesPlainErrorAs500(t *testing.T) {
	recorder, _ := runSetGinError(t, http.StatusInternalServerError,
		errors.New("some unrelated failure"))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for plain error, got %d", recorder.Code)
	}
}

// TestSetGinErrorDoesNotUpgradeNon500Statuses verifies the upgrade is
// scoped to the 500 path. A codes.Unavailable error wrapped in a 400 or
// 403 call must keep its original status, so the existing PermissionDenied
// -> 403 and NotFound -> 404 mappings in the controllers are not broken.
func TestSetGinErrorDoesNotUpgradeNon500Statuses(t *testing.T) {
	cases := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
	}

	for _, statusCode := range cases {
		t.Run(fmt.Sprintf("status=%d", statusCode), func(t *testing.T) {
			recorder, _ := runSetGinError(t, statusCode,
				status.Error(codes.Unavailable, "backend unreachable"))

			if recorder.Code != statusCode {
				t.Fatalf("expected %d to be preserved, got %d", statusCode, recorder.Code)
			}
		})
	}
}

// TestSetGinErrorWritesErrorMessage asserts the JSON body still carries the
// error message after the status upgrade.
func TestSetGinErrorWritesErrorMessage(t *testing.T) {
	recorder, body := runSetGinError(t, http.StatusInternalServerError,
		status.Error(codes.Unavailable, "connection refused"))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", recorder.Code)
	}
	if msg, _ := body["error"].(string); msg != "rpc error: code = Unavailable desc = connection refused" {
		t.Fatalf("unexpected error message: %v", body["error"])
	}
}
