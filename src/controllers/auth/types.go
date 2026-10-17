package auth

import (
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
)

// GetAccessTokenReply is the response of the GET /auth/access-token reply.
type GetAccessTokenReply struct {
	Token string `json:"token"`
}

// PostAccessTokenRequest is the body of POST /auth/public-access-token.
// The user authenticates by share id; no session cookie is required.
type PostAccessTokenRequest struct {
	// verify with the ID of a share
	ShareId string `json:"share_id"`
}

// LoginRequest is the body of POST /api/auth/login. Today the
// controller only accepts `kind: "password"`; passkey login goes
// through the /auth/passkey/login/{begin,finish} endpoints and
// OAuth flows (Discord, Google) keep their dedicated routes.
//
// The password is sent in plaintext over the wire (HTTPS in front)
// and hashed server-side before reaching gRPC.
type LoginRequest struct {
	Kind auth.Kind `json:"kind" example:"password"`

	// Password fields
	Email    string `json:"email,omitempty" example:"alice@example.com"`
	Password string `json:"password,omitempty" example:"correct horse battery staple"`
}

// SignupRequest is the body of POST /api/auth/signup. Splitting
// signup from login keeps the controller's branching explicit
// (signup is a separate code path on the gRPC side too).
type SignupRequest struct {
	Email    string `json:"email" example:"alice@example.com"`
	Username string `json:"username" example:"alice"`
	Password string `json:"password" example:"correct horse battery staple"`
}

// PostUserRequest is the body for POST /api/users: clients send a
// plaintext password, the server hashes it server-side before
// reaching the auth gRPC service.
type PostUserRequest struct {
	Email     string `json:"email" binding:"required" example:"alice@example.com"`
	Username  string `json:"username" binding:"required" example:"alice"`
	Password  string `json:"password" binding:"required" example:"correct horse battery staple"`
	AvatarURL string `json:"avatar_url,omitempty" example:"https://cdn.example.com/avatars/alice.png"`
}

// PatchUserRequest is the body for PATCH /api/users/:id: each field
// is tri-state (omit / set / clear) and set+clear is rejected as 400.
type PatchUserRequest struct {
	Username             *string    `json:"username,omitempty" example:"alice"`
	UsernameClear        bool       `json:"username_clear,omitempty" example:"false"`
	Email                *string    `json:"email,omitempty" example:"alice@example.com"`
	EmailClear           bool       `json:"email_clear,omitempty" example:"false"`
	EmailVerifiedAt      *time.Time `json:"email_verified_at,omitempty" example:"2026-10-12T10:00:00Z"`
	EmailVerifiedAtClear bool       `json:"email_verified_at_clear,omitempty" example:"false"`
	AvatarURL            *string    `json:"avatar_url,omitempty" example:"https://cdn.example.com/avatars/alice.png"`
	AvatarURLClear       bool       `json:"avatar_url_clear,omitempty" example:"false"`
}

// LinkPasswordRequest carries a plaintext password; the server
// hashes it (argon2id) before reaching gRPC.
type LinkPasswordRequest struct {
	Password string `json:"password"`
}

// ChangePasswordRequest is the body of POST /auth/password/change.
// Both passwords are plaintext, hashed server-side. The current
// password is hashed and constant-time-compared against the stored
// hash; the new password replaces the credential on success.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// PasskeyCeremonyBeginRequest kicks off a WebAuthn ceremony on the
// server. The body is optional.
//
// For the registration flow the caller MUST supply a UserId of an
// already-existing user -- passkey-only signup (no password) is not
// supported yet; the frontend should mint a password user via
// /auth/signup first, then attach a passkey via /auth/link/passkey.
// The login flow ignores the body entirely.
type PasskeyCeremonyBeginRequest struct {
	UserId string `json:"user_id,omitempty"`
}

// PasskeyCeremonyBeginReply is the response of a /begin endpoint:
// the ceremony envelope the browser feeds to navigator.credentials,
// the session key the matching /finish echoes back, and -- on
// /link/passkey/begin only -- the server-supplied user handle the
// frontend copies into options.user instead of reading a cache.
//
// `challenge` is duplicated at the top level so a caller that
// reads `data.challenge` directly (the natural shape for
// PublicKeyCredentialCreationOptions) does not need to dig into
// `data.options`. The ceremony envelope itself remains in
// `options` for callers that already wire it that way.
type PasskeyCeremonyBeginReply struct {
	SessionKey string         `json:"session_key"`
	Challenge  string         `json:"challenge,omitempty"`
	Options    map[string]any `json:"options,omitempty"`
	UserID     string         `json:"user_id,omitempty"`
	UserName   string         `json:"user_name,omitempty"`
}

// PasskeyCeremonyFinishRequest is the body posted to the `/finish`
// endpoints. The browser delivers the resolved `PublicKeyCredential`
// exactly as `JSON.stringify(navigator.credentials.{create,get}())`
// produces it; binary fields (rawId, attestationObject,
// authenticatorData, signature, userHandle) are base64url-no-pad
// strings so the JSON encoder does not drop the ArrayBuffers.
//
// `session_key` is the nonce the server returned on /begin;
// `friendly_name` is an optional human-readable label carried only
// for registration / link paths (used by `RegisterPasskey`). Login
// ceremonies never supply `friendly_name`.
//
// The lib (`go-webauthn/webauthn`) parses the lib-shaped
// `CredentialCreationResponse` / `CredentialAssertionResponse`
// directly from `c.Request.Body`, so the /finish handlers rebuild
// the request body to be exactly `req.Credential` JSON before
// calling `FinishRegistration` / `FinishPasskeyLogin`.
//
// Authoritative field shapes are pinned by the SPA hook tests
// (`expectBase64UrlNoPad`).
type PasskeyCeremonyFinishRequest struct {
	SessionKey   string                  `json:"session_key"`
	FriendlyName string                  `json:"friendly_name,omitempty"`
	Credential   PasskeyFinishCredential `json:"credential"`
}

// PasskeyFinishCredential mirrors the JSON-serialized shape the
// browser produces. Two response branches:
//   - register / link: response carries `clientDataJSON`,
//     `attestationObject`, optional `transports`.
//   - login: response carries `clientDataJSON`,
//     `authenticatorData`, `signature`, optional `userHandle`.
type PasskeyFinishCredential struct {
	ID                      string            `json:"id"`
	RawID                   string            `json:"rawId"`
	Type                    string            `json:"type"`
	AuthenticatorAttachment string            `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any    `json:"clientExtensionResults,omitempty"`
	Response                PasskeyFinishResp `json:"response"`
}

// PasskeyFinishResp holds whichever response fields the browser sent;
// the tag `omitempty` keeps the wire JSON byte-for-byte identical to
// what the SPA produced (so go-webauthn's strict parser is happy).
type PasskeyFinishResp struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject,omitempty"`
	Transports        []string `json:"transports,omitempty"`
	AuthenticatorData string   `json:"authenticatorData,omitempty"`
	Signature         string   `json:"signature,omitempty"`
	UserHandle        string   `json:"userHandle,omitempty"`
}

// PasskeyCeremonyFinishReply is the success body returned by the
// `/finish` endpoints after a verified ceremony. The login variant
// returns the user via the session cookie + 200 with the parsed
// UserAuth body (kept consistent with `loginUser`).
type PasskeyCeremonyFinishReply struct {
	CredentialId string `json:"credential_id"`
}
