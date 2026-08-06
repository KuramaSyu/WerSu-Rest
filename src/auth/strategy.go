// Package auth contains the login strategy layer that runs on the
// REST side of the auth boundary. The gRPC backend (WerSu-gRPC) is
// the source of truth for users and credentials; the strategies here
// orchestrate the side effects that happen *before* the gRPC call --
// OAuth callbacks, password hashing, WebAuthn ceremony validation --
// and then persist the verified result via AuthService.
//
// A strategy is constructed with the inputs it needs and the gRPC
// client it talks to. Calling Login() returns a *proto.UserAuth on
// success or an error otherwise. The orchestrator (the auth controller
// handler) dispatches to the right strategy based on the `kind` field
// of the incoming request.
package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// AuthServiceClientIface is the slice of the gRPC AuthServiceClient
// surface that the strategies and the controller depend on. Defining
// the interface here (rather than passing the concrete
// *proto.AuthServiceClient) lets tests substitute a fake without
// spinning up a real gRPC server.
//
// The interface stays small on purpose: each strategy declares
// which methods it actually uses; the fake only needs to implement
// the ones the test exercises.
type AuthServiceClientIface interface {
	CreateUserAuth(ctx context.Context, in *proto.CreateUserAuthRequest, opts ...grpc.CallOption) (*proto.CreateUserAuthResponse, error)
	GetUserAuth(ctx context.Context, in *proto.GetUserAuthRequest, opts ...grpc.CallOption) (*proto.GetUserAuthResponse, error)
	UpdateUserAuth(ctx context.Context, in *proto.UpdateUserAuthRequest, opts ...grpc.CallOption) (*proto.UpdateUserAuthResponse, error)
	FindCredentialByProvider(ctx context.Context, in *proto.FindCredentialByProviderRequest, opts ...grpc.CallOption) (*proto.FindCredentialByProviderResponse, error)
	FindPasskey(ctx context.Context, in *proto.FindPasskeyRequest, opts ...grpc.CallOption) (*proto.FindPasskeyResponse, error)
	ListPasskeys(ctx context.Context, in *proto.ListPasskeysRequest, opts ...grpc.CallOption) (*proto.ListPasskeysResponse, error)
	RegisterPasskey(ctx context.Context, in *proto.RegisterPasskeyRequest, opts ...grpc.CallOption) (*proto.RegisterPasskeyResponse, error)
	UpdatePasskeyCounter(ctx context.Context, in *proto.UpdatePasskeyCounterRequest, opts ...grpc.CallOption) (*proto.UpdatePasskeyCounterResponse, error)
	RevokePasskey(ctx context.Context, in *proto.RevokePasskeyRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	LinkCredential(ctx context.Context, in *proto.LinkCredentialRequest, opts ...grpc.CallOption) (*proto.LinkCredentialResponse, error)
	UnlinkCredential(ctx context.Context, in *proto.UnlinkCredentialRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	ListLinkedCredentials(ctx context.Context, in *proto.ListLinkedCredentialsRequest, opts ...grpc.CallOption) (*proto.ListLinkedCredentialsResponse, error)
}

// Compile-time check: the generated AuthServiceClient interface
// (returned by proto.NewAuthServiceClient) satisfies
// AuthServiceClientIface. The strategies hold the interface type;
// the wiring in main.go passes the concrete client.
var _ AuthServiceClientIface = (proto.AuthServiceClient)(nil)

// LoginStrategy is the contract every provider-specific login flow
// implements. Methods on it are non-idempotent: a successful Login
// creates or resumes a session; the caller is responsible for issuing
// the JWT after.
//
// The strategy is intentionally narrow: it does not know about HTTP,
// sessions, or cookies. It takes inputs (already verified by the
// caller or by the WebAuthn handler), talks to gRPC, and returns a
// UserAuth. The controller glues that to a session cookie.
type LoginStrategy interface {
	// Login returns the authenticated user. The returned error may
	// carry a gRPC status code (codes.NotFound, codes.AlreadyExists,
	// codes.PermissionDenied) for the controller to map to HTTP.
	Login(ctx context.Context) (*proto.UserAuth, error)
}

// Kind identifies which strategy the orchestrator should dispatch to.
//
// The wire format is a plain string in the request body so the
// frontend can say "login via password" without having to know about
// the gRPC enum values.
type Kind string

const (
	KindDiscord Kind = "discord"
	KindGoogle  Kind = "google"
	KindPassword Kind = "password"
	KindPasskeyKind Kind = "passkey"
)

// ResolveKind maps the wire string to the canonical Kind. Unknown
// values fall through to the empty string and the orchestrator
// responds with 400.
func ResolveKind(s string) (Kind, bool) {
	switch Kind(s) {
	case KindDiscord, KindGoogle, KindPassword, KindPasskeyKind:
		return Kind(s), true
	}
	return "", false
}
