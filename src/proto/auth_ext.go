package proto

import (
	"errors"
	"fmt"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
)

// --- Oneof payload accessors -----------------------------------------
//
// The `Credential` and `LinkCredentialRequest` messages use a
// proto-level `oneof payload` to express "exactly one of discord_id /
// password_hash / passkey_id / google_id is populated". The generated
// stubs expose this as the `GetPayload()` method which returns a
// dynamically-typed wrapper. These helpers unwrap to the concrete
// primitive the controllers actually want.

// CredentialPayload returns the populated credential payload string
// for a `Credential` row. Returns an error if the row is empty or
// carries a payload type that has no string representation (none in
// the current schema; future fields might add bytes).
func (c *Credential) CredentialPayload() (string, error) {
	if c == nil {
		return "", errors.New("nil credential")
	}
	switch p := c.GetPayload().(type) {
	case *Credential_DiscordId:
		return p.DiscordId, nil
	case *Credential_PasswordHash:
		return p.PasswordHash, nil
	case *Credential_PasskeyId:
		return p.PasskeyId, nil
	case *Credential_GoogleId:
		return p.GoogleId, nil
	}
	return "", fmt.Errorf("credential has no payload set (kind=%v)", c.GetKind())
}

// LinkCredentialPayload extracts the populated `payload` field from a
// `LinkCredentialRequest`. The same shape as `CredentialPayload` but
// for the request message.
func (r *LinkCredentialRequest) LinkCredentialPayload() (string, error) {
	if r == nil {
		return "", errors.New("nil request")
	}
	switch p := r.GetPayload().(type) {
	case *LinkCredentialRequest_DiscordId:
		return p.DiscordId, nil
	case *LinkCredentialRequest_PasswordHash:
		return p.PasswordHash, nil
	case *LinkCredentialRequest_PasskeyId:
		return p.PasskeyId, nil
	case *LinkCredentialRequest_GoogleId:
		return p.GoogleId, nil
	}
	return "", fmt.Errorf("link request has no payload set (kind=%v)", r.GetKind())
}

// --- UserAuth <-> models.User ------------------------------------------

// ToUser converts a `UserAuth` (the auth-proto user shape) into the
// project's existing `models.User` (the legacy Discord-shaped user).
//
// The legacy `models.User` is shaped around Discord's profile fields
// (avatar, discriminator, snowflake ID). The auth proto doesn't carry
// those -- they're Discord-provider-specific metadata, not auth data.
// ToUser leaves the Discord-shaped fields at their zero value and the
// callers that need a Discord user must fetch the Discord credential
// separately if they need it.
func (u *UserAuth) ToUser() *models.User {
	if u == nil {
		return nil
	}
	return &models.User{
		ID:    u.Id,
		Email: u.Email,
	}
}

// ParseJS returns a JSON-serializable view of the authenticated user.
// `email_verified` is derived from the zero-value check on the
// timestamp; an empty Timestamp means "not verified".
func (u *UserAuth) ParseJS() *models.JsUserAuth {
	if u == nil {
		return nil
	}
	return &models.JsUserAuth{
		ID:              u.Id,
		Email:           u.Email,
		Username:        u.Username,
		EmailVerifiedAt: u.EmailVerifiedAt.AsTime(),
		IsActive:        u.IsActive,
		AvatarURL:       u.AvatarUrl,
	}
}

// --- UpdateUserAuthRequest tri-state builders --------------------------
//
// The tri-state update (omit / set / clear) is encoded as a `oneof`
// per field. These helpers build the request message from a typed
// intent so the controllers don't reach into the proto oneofs
// directly. They are unused at the moment (no PATCH /auth/me endpoint
// yet) and are kept here so the typed entry point is in one place.
