package auth

import (
	"bytes"
	"context"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// WebAuthnUser implements webauthn.User for the app's UserAuth row.
// Credentials carries the gRPC passkey id alongside the webauthn
// fields so the controller can update the sign counter without a
// second lookup.
type WebAuthnUser struct {
	UserAuth    *proto.UserAuth
	Credentials []WebAuthnCredential
}

// WebAuthnCredential is webauthn.Credential plus the gRPC passkey id.
type WebAuthnCredential struct {
	webauthn.Credential
	PasskeyID string
}

func NewWebAuthnUser(user *proto.UserAuth, passkeys []*proto.Passkey) *WebAuthnUser {
	creds := make([]WebAuthnCredential, 0, len(passkeys))
	for _, pk := range passkeys {
		if pk == nil {
			continue
		}
		creds = append(creds, WebAuthnCredential{
			Credential: protoPasskeyToWebauthnCredential(pk),
			PasskeyID:  pk.GetId(),
		})
	}
	return &WebAuthnUser{UserAuth: user, Credentials: creds}
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.Credentials))
	for i, c := range u.Credentials {
		out[i] = c.Credential
	}
	return out
}

// FindCredential returns the wrapper matching the raw credential id, or nil.
func (u *WebAuthnUser) FindCredential(id []byte) *WebAuthnCredential {
	for i, c := range u.Credentials {
		if bytes.Equal(c.Credential.ID, id) {
			return &u.Credentials[i]
		}
	}
	return nil
}

// WebAuthnID returns the User Handle (the app's user id as bytes).
func (u *WebAuthnUser) WebAuthnID() []byte {
	if u.UserAuth == nil || u.UserAuth.GetId() == "" {
		return []byte("anonymous")
	}
	return []byte(u.UserAuth.GetId())
}

// WebAuthnName / WebAuthnDisplayName feed the authenticator's passkey picker.
func (u *WebAuthnUser) WebAuthnName() string {
	if u.UserAuth == nil {
		return ""
	}
	if name := u.UserAuth.GetUsername(); name != "" {
		return name
	}
	return u.UserAuth.GetEmail()
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.WebAuthnName()
}

func protoPasskeyToWebauthnCredential(pk *proto.Passkey) webauthn.Credential {
	flags := webauthn.CredentialFlags{
		UserPresent:    true,
		UserVerified:   pk.GetUserVerified(),
		BackupEligible: pk.GetBackupEligible(),
		BackupState:    pk.GetBackupState(),
	}
	auth := webauthn.Authenticator{
		AAGUID:    pk.GetAaguid(),
		SignCount: uint32(pk.GetSignCount()),
	}
	transports := make([]protocol.AuthenticatorTransport, 0, len(pk.GetTransports()))
	for _, t := range pk.GetTransports() {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:            pk.GetCredentialId(),
		PublicKey:     pk.GetPublicKey(),
		Authenticator: auth,
		Flags:         flags,
		Transport:     transports,
	}
}

// ErrPasskeyUserNotFound signals an empty/anonymous User Handle from the browser.
var ErrPasskeyUserNotFound = errors.New("passkey user not found")

// WebAuthnUserResolver is the discoverable-login handler. It maps a
// User Handle (the app's user id) to a *WebAuthnUser by calling gRPC.
func WebAuthnUserResolver(ctx context.Context, authSvc AuthServiceClientIface) webauthn.DiscoverableUserHandler {
	return func(_, userHandle []byte) (webauthn.User, error) {
		userId := string(userHandle)
		if userId == "" || userId == "anonymous" {
			return nil, ErrPasskeyUserNotFound
		}
		userResp, err := authSvc.GetUserAuth(ctx, &proto.GetUserAuthRequest{
			Identifier: &proto.GetUserAuthRequest_UserId{UserId: userId},
		})
		if err != nil {
			return nil, err
		}
		pkResp, err := authSvc.ListPasskeys(ctx, &proto.ListPasskeysRequest{
			UserId: userId,
		})
		if err != nil {
			return nil, err
		}
		return NewWebAuthnUser(userResp.GetUser(), pkResp.GetPasskeys()), nil
	}
}

// LoadPasskeyUser fetches a user + their passkeys by id. Used by the
// link endpoints, which already know the user from the session.
func LoadPasskeyUser(ctx context.Context, authSvc AuthServiceClientIface, userId string) (*WebAuthnUser, error) {
	userResp, err := authSvc.GetUserAuth(ctx, &proto.GetUserAuthRequest{
		Identifier: &proto.GetUserAuthRequest_UserId{UserId: userId},
	})
	if err != nil {
		return nil, err
	}
	pkResp, err := authSvc.ListPasskeys(ctx, &proto.ListPasskeysRequest{
		UserId: userId,
	})
	if err != nil {
		return nil, err
	}
	return NewWebAuthnUser(userResp.GetUser(), pkResp.GetPasskeys()), nil
}
