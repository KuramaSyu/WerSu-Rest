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
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// FakeAuthClient is a hand-rolled fake of AuthServiceClientIface.
// Tests configure the desired response for each method by setting
// the corresponding `On*` field on the fake before invoking the
// strategy. Methods that are not configured return (nil, "<Method>
// not configured").
//
// The fake is exported so other packages (e.g. controllers) can use
// the same plumbing in their tests without re-implementing it.
type FakeAuthClient struct {
	OnCreateUserAuth        func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error)
	OnGetUserAuth           func(*proto.GetUserAuthRequest) (*proto.GetUserAuthResponse, error)
	OnFindCredentialByProv  func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error)
	OnFindPasskey           func(*proto.FindPasskeyRequest) (*proto.FindPasskeyResponse, error)
	OnRegisterPasskey       func(*proto.RegisterPasskeyRequest) (*proto.RegisterPasskeyResponse, error)
	OnUpdateUserAuth        func(*proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error)
	OnListPasskeys          func(*proto.ListPasskeysRequest) (*proto.ListPasskeysResponse, error)
	OnUpdatePasskeyCounter  func(*proto.UpdatePasskeyCounterRequest) (*proto.UpdatePasskeyCounterResponse, error)
	OnRevokePasskey         func(*proto.RevokePasskeyRequest) (*emptypb.Empty, error)
	OnLinkCredential        func(*proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error)
	OnUnlinkCredential      func(*proto.UnlinkCredentialRequest) (*emptypb.Empty, error)
	OnListLinkedCredentials func(*proto.ListLinkedCredentialsRequest) (*proto.ListLinkedCredentialsResponse, error)
}

func (f *FakeAuthClient) CreateUserAuth(ctx context.Context, in *proto.CreateUserAuthRequest, opts ...grpc.CallOption) (*proto.CreateUserAuthResponse, error) {
	if f.OnCreateUserAuth == nil {
		return nil, errors.New("CreateUserAuth not configured on fake")
	}
	return f.OnCreateUserAuth(in)
}

func (f *FakeAuthClient) GetUserAuth(ctx context.Context, in *proto.GetUserAuthRequest, opts ...grpc.CallOption) (*proto.GetUserAuthResponse, error) {
	if f.OnGetUserAuth == nil {
		return nil, errors.New("GetUserAuth not configured on fake")
	}
	return f.OnGetUserAuth(in)
}

func (f *FakeAuthClient) FindCredentialByProvider(ctx context.Context, in *proto.FindCredentialByProviderRequest, opts ...grpc.CallOption) (*proto.FindCredentialByProviderResponse, error) {
	if f.OnFindCredentialByProv == nil {
		return nil, errors.New("FindCredentialByProvider not configured on fake")
	}
	return f.OnFindCredentialByProv(in)
}

func (f *FakeAuthClient) FindPasskey(ctx context.Context, in *proto.FindPasskeyRequest, opts ...grpc.CallOption) (*proto.FindPasskeyResponse, error) {
	if f.OnFindPasskey == nil {
		return nil, errors.New("FindPasskey not configured on fake")
	}
	return f.OnFindPasskey(in)
}

func (f *FakeAuthClient) RegisterPasskey(ctx context.Context, in *proto.RegisterPasskeyRequest, opts ...grpc.CallOption) (*proto.RegisterPasskeyResponse, error) {
	if f.OnRegisterPasskey == nil {
		return nil, errors.New("RegisterPasskey not configured on fake")
	}
	return f.OnRegisterPasskey(in)
}

func (f *FakeAuthClient) UpdateUserAuth(ctx context.Context, in *proto.UpdateUserAuthRequest, opts ...grpc.CallOption) (*proto.UpdateUserAuthResponse, error) {
	if f.OnUpdateUserAuth == nil {
		return nil, errors.New("UpdateUserAuth not configured on fake")
	}
	return f.OnUpdateUserAuth(in)
}

func (f *FakeAuthClient) ListPasskeys(ctx context.Context, in *proto.ListPasskeysRequest, opts ...grpc.CallOption) (*proto.ListPasskeysResponse, error) {
	if f.OnListPasskeys == nil {
		return nil, errors.New("ListPasskeys not configured on fake")
	}
	return f.OnListPasskeys(in)
}

func (f *FakeAuthClient) UpdatePasskeyCounter(ctx context.Context, in *proto.UpdatePasskeyCounterRequest, opts ...grpc.CallOption) (*proto.UpdatePasskeyCounterResponse, error) {
	if f.OnUpdatePasskeyCounter == nil {
		return nil, errors.New("UpdatePasskeyCounter not configured on fake")
	}
	return f.OnUpdatePasskeyCounter(in)
}

func (f *FakeAuthClient) RevokePasskey(ctx context.Context, in *proto.RevokePasskeyRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if f.OnRevokePasskey == nil {
		return nil, errors.New("RevokePasskey not configured on fake")
	}
	return f.OnRevokePasskey(in)
}

func (f *FakeAuthClient) LinkCredential(ctx context.Context, in *proto.LinkCredentialRequest, opts ...grpc.CallOption) (*proto.LinkCredentialResponse, error) {
	if f.OnLinkCredential == nil {
		return nil, errors.New("LinkCredential not configured on fake")
	}
	return f.OnLinkCredential(in)
}

func (f *FakeAuthClient) UnlinkCredential(ctx context.Context, in *proto.UnlinkCredentialRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if f.OnUnlinkCredential == nil {
		return nil, errors.New("UnlinkCredential not configured on fake")
	}
	return f.OnUnlinkCredential(in)
}

func (f *FakeAuthClient) ListLinkedCredentials(ctx context.Context, in *proto.ListLinkedCredentialsRequest, opts ...grpc.CallOption) (*proto.ListLinkedCredentialsResponse, error) {
	if f.OnListLinkedCredentials == nil {
		return nil, errors.New("ListLinkedCredentials not configured on fake")
	}
	return f.OnListLinkedCredentials(in)
}

// Compile-time check that the fake satisfies the interface.
var _ AuthServiceClientIface = (*FakeAuthClient)(nil)
