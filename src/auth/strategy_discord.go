package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"

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
	Auth          AuthServiceClientIface
	DiscordId     int64
	Username      string
	Avatar        string
	Email         string
	Discriminator string

	// AvatarUrl is the resolved absolute URL to the user's avatar.
	// The controller sets this to the Discord CDN URL when the user
	// has a custom avatar, or empty string if Discord didn't provide
	// one. The strategy propagates it to CreateUserAuth.
	AvatarUrl string
}

// Login implements LoginStrategy.
func (s *DiscordStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}

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

	email := s.Email
	if email == "" {
		email = discordPlaceholderEmail(s.DiscordId)
	}

	createResp, err := s.Auth.CreateUserAuth(ctx, &proto.CreateUserAuthRequest{
		Email:        email,
		Username:     s.Username,
		PasswordHash: "",
		AvatarUrl:    s.AvatarUrl,
	})
	if err != nil {
		if isAlreadyExists(err) {
			// Race: another concurrent callback already created
			// the user. Re-fetch by DiscordId and surface an error
			// if the credential still isn't there -- that means
			// the email row exists but no Discord link was ever
			// inserted, so we can't hand the user back.
			r, err := s.Auth.FindCredentialByProvider(ctx, &proto.FindCredentialByProviderRequest{
				Kind:       proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
				Identifier: &proto.FindCredentialByProviderRequest_DiscordId{DiscordId: did},
			})
			if err != nil {
				return nil, err
			}
			if r.GetUser() == nil {
				return nil, fmt.Errorf("discord credential %d not linked after race", did)
			}
			return r.GetUser(), nil
		}
		return nil, err
	}

	// `CreateUserAuth` creates the user row only -- the Discord
	// credential lives in a separate row and must be linked via
	// `LinkCredential`. Without this call, the next login lookup
	// returns NotFound and we fall into the AlreadyExists branch
	// with nothing to return.
	user := createResp.GetUser()
	if _, err := s.Auth.LinkCredential(ctx, &proto.LinkCredentialRequest{
		UserId:      user.GetId(),
		RequesterId: user.GetId(),
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
		Payload:     &proto.LinkCredentialRequest_DiscordId{DiscordId: strconv.FormatInt(did, 10)},
	}); err != nil {
		return nil, fmt.Errorf("link discord credential: %w", err)
	}

	return user, nil
}

// discordPlaceholderEmail is a deterministic unique email for users
// who haven't shared a real one. The `users.d.noreply.discord` host
// is reserved by Discord for this purpose and never delivers email.
func discordPlaceholderEmail(discordId int64) string {
	return formatPlaceholder(discordId)
}
