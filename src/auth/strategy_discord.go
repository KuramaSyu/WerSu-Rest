package auth

import (
	"context"
	"errors"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// DiscordStrategy completes a Discord login. The OAuth code exchange
// has already happened by the time this is constructed -- the
// controller calls OAuthConfig.Exchange, fetches the profile from
// discord.com/api/users/@me, and passes the verified DiscordUser here.
//
// The gRPC backend does no auth verification for Discord; it just
// stores the (DiscordId, Username, Avatar, Discriminator) tuple on
// either a new user or an existing one. If the existing user is
// found by DiscordId, the strategy links no new credential (the link
// already exists). If not found, the strategy creates the user --
// and because the user has no email from Discord, the email field
// is left empty.
type DiscordStrategy struct {
	Auth      AuthServiceClientIface
	DiscordId int64
	Username  string
	Avatar    string
	Email     string
	Discriminator string
}

// Login implements LoginStrategy.
func (s *DiscordStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}

	// 1. Look up existing user by DiscordId via the credential
	// lookup RPC. Going through FindCredentialByProviderRequest
	// (rather than GetUserAuthRequest) means the gRPC service is the
	// single source of truth for "this provider id maps to that
	// user".
	did := s.DiscordId
	resp, err := s.Auth.FindCredentialByProvider(ctx, &proto.FindCredentialByProviderRequest{
		Kind:       proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
		Identifier: &proto.FindCredentialByProviderRequest_DiscordId{DiscordId: did},
	})
	if err == nil {
		return resp.GetUser(), nil
	}
	if !isNotFound(err) {
		return nil, err
	}

	// 2. Create a new user. The auth.proto CreateUserAuth always
	// wants a password-less row when invoked without a credential
	// payload (the password is intentionally a separate credential).
	// We pass an empty password_hash so the gRPC service layer
	// creates a user with no password credential.
	// Provide a placeholder email when Discord doesn't share one --
	// the auth schema requires email to be unique, and Discord's
	// optional `email` scope must be granted for the value to be
	// populated. We use a deterministic placeholder so the unique
	// constraint is satisfied without leaking the user's real state.
	// The placeholder is replaced when the user links a password.
	email := s.Email
	if email == "" {
		email = discordPlaceholderEmail(s.DiscordId)
	}

	createResp, err := s.Auth.CreateUserAuth(ctx, &proto.CreateUserAuthRequest{
		Email:        email,
		Username:     s.Username,
		PasswordHash: "",
	})
	if err != nil {
		if isAlreadyExists(err) {
			// Race: another concurrent callback already created
			// the user. Re-fetch by DiscordId.
			r, err := s.Auth.FindCredentialByProvider(ctx, &proto.FindCredentialByProviderRequest{
				Kind:       proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
				Identifier: &proto.FindCredentialByProviderRequest_DiscordId{DiscordId: did},
			})
			if err != nil {
				return nil, err
			}
			return r.GetUser(), nil
		}
		return nil, err
	}
	return createResp.GetUser(), nil
}

// discordPlaceholderEmail is a deterministic unique email for users
// who haven't shared a real one. The `users.d.noreply.discord` host
// is reserved by Discord for this purpose and never delivers email.
func discordPlaceholderEmail(discordId int64) string {
	return formatPlaceholder(discordId)
}
