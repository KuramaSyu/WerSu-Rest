package proto

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------- CredentialPayload ----------

func TestCredentialPayloadDiscord(t *testing.T) {
	c := &Credential{
		Id:      "c-1",
		Kind:    CredentialKind_CREDENTIAL_KIND_DISCORD,
		Payload: &Credential_DiscordId{DiscordId: "12345"},
	}
	got, err := c.CredentialPayload()
	if err != nil {
		t.Fatalf("CredentialPayload: %v", err)
	}
	if got != "12345" {
		t.Errorf("payload = %q, want 12345", got)
	}
}

func TestCredentialPayloadPassword(t *testing.T) {
	c := &Credential{
		Kind:    CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload: &Credential_PasswordHash{PasswordHash: "$argon2id$v=19$..."},
	}
	got, err := c.CredentialPayload()
	if err != nil {
		t.Fatalf("CredentialPayload: %v", err)
	}
	if got != "$argon2id$v=19$..." {
		t.Errorf("payload = %q", got)
	}
}

func TestCredentialPayloadPasskey(t *testing.T) {
	c := &Credential{
		Kind:    CredentialKind_CREDENTIAL_KIND_PASSKEY,
		Payload: &Credential_PasskeyId{PasskeyId: "pk-1"},
	}
	got, err := c.CredentialPayload()
	if err != nil {
		t.Fatalf("CredentialPayload: %v", err)
	}
	if got != "pk-1" {
		t.Errorf("payload = %q", got)
	}
}

func TestCredentialPayloadGoogle(t *testing.T) {
	c := &Credential{
		Kind:    CredentialKind_CREDENTIAL_KIND_GOOGLE,
		Payload: &Credential_GoogleId{GoogleId: "sub-abc"},
	}
	got, err := c.CredentialPayload()
	if err != nil {
		t.Fatalf("CredentialPayload: %v", err)
	}
	if got != "sub-abc" {
		t.Errorf("payload = %q", got)
	}
}

func TestCredentialPayloadEmpty(t *testing.T) {
	c := &Credential{Kind: CredentialKind_CREDENTIAL_KIND_DISCORD}
	_, err := c.CredentialPayload()
	if err == nil {
		t.Fatal("expected error for credential with no payload")
	}
	if !strings.Contains(err.Error(), "no payload") {
		t.Errorf("error text = %q, want one mentioning 'no payload'", err.Error())
	}
}

func TestCredentialPayloadNil(t *testing.T) {
	var c *Credential
	if _, err := c.CredentialPayload(); err == nil {
		t.Fatal("expected error for nil credential")
	}
}

// ---------- LinkCredentialPayload ----------

func TestLinkCredentialPayloadAllKinds(t *testing.T) {
	cases := []struct {
		name string
		req  *LinkCredentialRequest
		want string
	}{
		{
			"discord",
			&LinkCredentialRequest{
				Kind:    CredentialKind_CREDENTIAL_KIND_DISCORD,
				Payload: &LinkCredentialRequest_DiscordId{DiscordId: "12345"},
			},
			"12345",
		},
		{
			"password",
			&LinkCredentialRequest{
				Kind:    CredentialKind_CREDENTIAL_KIND_PASSWORD,
				Payload: &LinkCredentialRequest_PasswordHash{PasswordHash: "hash"},
			},
			"hash",
		},
		{
			"passkey",
			&LinkCredentialRequest{
				Kind:    CredentialKind_CREDENTIAL_KIND_PASSKEY,
				Payload: &LinkCredentialRequest_PasskeyId{PasskeyId: "pk-1"},
			},
			"pk-1",
		},
		{
			"google",
			&LinkCredentialRequest{
				Kind:    CredentialKind_CREDENTIAL_KIND_GOOGLE,
				Payload: &LinkCredentialRequest_GoogleId{GoogleId: "sub-abc"},
			},
			"sub-abc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.req.LinkCredentialPayload()
			if err != nil {
				t.Fatalf("LinkCredentialPayload: %v", err)
			}
			if got != tc.want {
				t.Errorf("payload = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLinkCredentialPayloadEmpty(t *testing.T) {
	r := &LinkCredentialRequest{Kind: CredentialKind_CREDENTIAL_KIND_DISCORD}
	if _, err := r.LinkCredentialPayload(); err == nil {
		t.Fatal("expected error for request with no payload")
	}
}

func TestLinkCredentialPayloadNil(t *testing.T) {
	var r *LinkCredentialRequest
	if _, err := r.LinkCredentialPayload(); err == nil {
		t.Fatal("expected error for nil request")
	}
}

// ---------- UserAuth.ParseJS ----------

func TestUserAuthParseJSBasic(t *testing.T) {
	u := &UserAuth{
		Id:    "u-1",
		Email: "alice@example.com",
	}
	js := u.ParseJS()
	if js == nil {
		t.Fatal("ParseJS returned nil")
	}
	if js.ID != "u-1" {
		t.Errorf("ID = %q, want u-1", js.ID)
	}
	if js.Email != "alice@example.com" {
		t.Errorf("Email = %q", js.Email)
	}
	if js.IsActive {
		t.Errorf("IsActive = true, want false")
	}
}

func TestUserAuthParseJSWithUsername(t *testing.T) {
	u := &UserAuth{
		Id:       "u-2",
		Email:    "bob@example.com",
		Username: "bob",
		IsActive: true,
	}
	js := u.ParseJS()
	if js.Username != "bob" {
		t.Errorf("Username = %q, want bob", js.Username)
	}
	if !js.IsActive {
		t.Errorf("IsActive = false, want true")
	}
}

func TestUserAuthParseJSWithVerifiedAt(t *testing.T) {
	ts := timestamppb.Now()
	u := &UserAuth{
		Id:              "u-3",
		Email:           "carol@example.com",
		EmailVerifiedAt: ts,
	}
	js := u.ParseJS()
	if !js.EmailVerifiedAt.Equal(ts.AsTime()) {
		t.Errorf("EmailVerifiedAt = %v, want %v", js.EmailVerifiedAt, ts.AsTime())
	}
}

func TestUserAuthParseJSNil(t *testing.T) {
	var u *UserAuth
	if js := u.ParseJS(); js != nil {
		t.Errorf("ParseJS of nil = %+v, want nil", js)
	}
}

// ---------- UserAuth.ToUser ----------

func TestUserAuthToUser(t *testing.T) {
	u := &UserAuth{Id: "u-1", Email: "alice@example.com"}
	got := u.ToUser()
	if got == nil {
		t.Fatal("ToUser returned nil")
	}
	if got.ID != "u-1" {
		t.Errorf("ID = %q", got.ID)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q", got.Email)
	}
	// The legacy Discord-shaped fields are intentionally left at
	// zero -- they're provider metadata, not auth identity.
	if got.DiscordId != 0 {
		t.Errorf("DiscordId = %d, want 0", got.DiscordId)
	}
	if got.Username != "" {
		t.Errorf("Username = %q, want empty", got.Username)
	}
}

func TestUserAuthToUserNil(t *testing.T) {
	var u *UserAuth
	if got := u.ToUser(); got != nil {
		t.Errorf("ToUser of nil = %+v, want nil", got)
	}
}
