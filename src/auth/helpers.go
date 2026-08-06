package auth

import (
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// isNotFound reports whether the gRPC error carries NotFound.
func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// isAlreadyExists reports whether the gRPC error carries AlreadyExists.
func isAlreadyExists(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}

// isPermissionDenied reports whether the gRPC error carries
// PermissionDenied.
func isPermissionDenied(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

// isFailedPrecondition reports whether the gRPC error carries
// FailedPrecondition (e.g. sign counter not strictly greater).
func isFailedPrecondition(err error) bool {
	return status.Code(err) == codes.FailedPrecondition
}

// formatPlaceholder builds the deterministic placeholder email for an
// OAuth user that hasn't shared a real email.
func formatPlaceholder(id int64) string {
	return "user-" + strconv.FormatInt(id, 10) + "@users.d.noreply.discord"
}

// nowTimestamp returns the current time as a protobuf Timestamp. Used
// for marking email_verified_at after a Google signup.
func nowTimestamp() *timestamppb.Timestamp {
	return timestamppb.New(time.Now())
}
