package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// GoogleStrategy completes a Google login. The OAuth dance has
// already happened by the time this is constructed -- the controller
// calls GoogleOAuthConfig.Exchange, fetches the userinfo endpoint,
// and passes the verified (GoogleId, Email, Name) here.
//
// The `google_id` is stable for life (Google's `sub` claim). The
// `email` is verified by Google (the `email_verified` field on the
// OpenID userinfo response indicates this) and we mark the auth
// user as email_verified when it's set.
type GoogleStrategy struct {
	Auth          AuthServiceClientIface
	GoogleId      string
	Email         string
	EmailVerified bool
	Username      string

	// AvatarUrl is the resolved absolute URL to the user's avatar.
	// The controller sets this to Google's `picture` URL when the
	// user has one, or empty string if Google didn't provide one.
	AvatarUrl string
}

// Login implements LoginStrategy.
func (s *GoogleStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}
	if s.GoogleId == "" {
		return nil, errors.New("google strategy requires GoogleId")
	}

	// 1. Look up by GoogleId via the credential lookup RPC.
	gid := s.GoogleId
	resp, err := s.Auth.FindCredentialByProvider(ctx, &proto.FindCredentialByProviderRequest{
		Kind:       proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
		Identifier: &proto.FindCredentialByProviderRequest_GoogleId{GoogleId: gid},
	})
	if err == nil {
		return resp.GetUser(), nil
	}
	if !isNotFound(err) {
		return nil, err
	}

	// 2. Create a new user. The email is verified by Google, so we
	// pass an empty password_hash and let the user set a password
	// later if they want one.
	createResp, err := s.Auth.CreateUserAuth(ctx, &proto.CreateUserAuthRequest{
		Email:        s.Email,
		Username:     s.Username,
		PasswordHash: "",
		AvatarUrl:    s.AvatarUrl,
	})
	if err != nil {
		if isAlreadyExists(err) {
			// Race: another concurrent callback already created
			// the user. Re-fetch by GoogleId and surface an error
			// if the credential still isn't there -- same shape
			// as the Discord path: orphan email, no link.
			r, err := s.Auth.FindCredentialByProvider(ctx, &proto.FindCredentialByProviderRequest{
				Kind:       proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
				Identifier: &proto.FindCredentialByProviderRequest_GoogleId{GoogleId: gid},
			})
			if err != nil {
				return nil, err
			}
			if r.GetUser() == nil {
				return nil, fmt.Errorf("google credential %q not linked after race", gid)
			}
			return r.GetUser(), nil
		}
		return nil, err
	}

	user := createResp.GetUser()

	// `CreateUserAuth` creates the user row only -- the Google
	// credential lives in a separate row and must be linked via
	// `LinkCredential`. Without this call, the next login lookup
	// returns NotFound and we fall into the AlreadyExists branch
	// with nothing to return.
	if _, err := s.Auth.LinkCredential(ctx, &proto.LinkCredentialRequest{
		UserId:      user.GetId(),
		RequesterId: user.GetId(),
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
		Payload:     &proto.LinkCredentialRequest_GoogleId{GoogleId: gid},
	}); err != nil {
		return nil, fmt.Errorf("link google credential: %w", err)
	}

	// Mark the email as verified on the just-created user. This
	// is a separate UpdateUserAuth call so that RejectUser-by-id
	// stays the simple "found by provider id" path.
	if s.EmailVerified && s.Email != "" {
		now := nowTimestamp()
		_, err = s.Auth.UpdateUserAuth(ctx, &proto.UpdateUserAuthRequest{
			UserId:      user.GetId(),
			RequesterId: user.GetId(),
			EmailVerifiedChange: &proto.UpdateUserAuthRequest_EmailVerifiedAtSet{
				EmailVerifiedAtSet: now,
			},
		})
		if err != nil && !isFailedPrecondition(err) {
			// Non-fatal: the email is still verified by Google, the
			// user just hasn't been promoted server-side. The next
			// login will retry.
			_ = err
		}
	}

	return user, nil
}
