package auth

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)
// ---------- Kind resolution ----------

func TestResolveKindKnown(t *testing.T) {
	cases := []string{"discord", "google", "password", "passkey"}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			if k, ok := ResolveKind(s); !ok || string(k) != s {
				t.Fatalf("ResolveKind(%q) = (%q, %v), want (%q, true)", s, k, ok, s)
			}
		})
	}
}

func TestResolveKindUnknown(t *testing.T) {
	cases := []string{"", "Discord", "PASSWORD", "magic-link", "jwt"}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			if k, ok := ResolveKind(s); ok {
				t.Fatalf("ResolveKind(%q) = (%q, true), want ('', false)", s, k)
			}
		})
	}
}

// ---------- DiscordStrategy ----------

func TestDiscordStrategyLoginExistingUser(t *testing.T) {
	want := &proto.UserAuth{Id: "u-1", Email: "discord@example.com"}

	var seen *proto.FindCredentialByProviderRequest
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			seen = in
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "cred-1", UserId: "u-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_DISCORD},
				User:       want,
			}, nil
		},
		OnCreateUserAuth: func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			t.Fatal("CreateUserAuth should not be called for an existing user")
			return nil, nil
		},
	}

	s := &DiscordStrategy{
		Auth:      fake,
		DiscordId: 12345,
		Username:  "alice",
		Avatar:    "abc",
		Email:     "discord@example.com",
	}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "u-1" {
		t.Errorf("user id = %q, want u-1", got.GetId())
	}
	if seen == nil || seen.GetDiscordId() != 12345 {
		t.Errorf("expected lookup with DiscordId=12345, got %+v", seen)
	}
	if seen.GetKind() != proto.CredentialKind_CREDENTIAL_KIND_DISCORD {
		t.Errorf("kind = %v, want DISCORD", seen.GetKind())
	}
}

func TestDiscordStrategyLoginCreatesUser(t *testing.T) {
	var created *proto.CreateUserAuthRequest
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, notFoundErr()
		},
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			created = in
			return &proto.CreateUserAuthResponse{
				User: &proto.UserAuth{Id: "new-u", Email: in.Email},
			}, nil
		},
	}

	s := &DiscordStrategy{
		Auth:      fake,
		DiscordId: 99999,
		Username:  "newuser",
		Email:     "real@example.com",
	}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "new-u" {
		t.Errorf("user id = %q, want new-u", got.GetId())
	}
	if created == nil {
		t.Fatal("CreateUserAuth was not called")
	}
	if created.Email != "real@example.com" {
		t.Errorf("created email = %q, want real@example.com", created.Email)
	}
	if created.PasswordHash != "" {
		t.Errorf("created password_hash = %q, want empty (no password for Discord users)", created.PasswordHash)
	}
}

func TestDiscordStrategyLoginPlaceholderEmail(t *testing.T) {
	// When Discord doesn't share an email, the strategy fills in
	// a deterministic placeholder so the unique-email constraint
	// doesn't crash.
	var created *proto.CreateUserAuthRequest
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, notFoundErr()
		},
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			created = in
			return &proto.CreateUserAuthResponse{User: &proto.UserAuth{Id: "u"}}, nil
		},
	}

	s := &DiscordStrategy{Auth: fake, DiscordId: 42, Username: "noemail"}
	if _, err := s.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if created.Email == "" {
		t.Fatal("placeholder email was empty")
	}
	if got := discordPlaceholderEmail(42); got != created.Email {
		t.Errorf("placeholder email = %q, want %q", created.Email, got)
	}
}

func TestDiscordStrategyLoginRaceAlreadyExists(t *testing.T) {
	// If the first lookup returns NotFound but the create races and
	// fails with AlreadyExists, the strategy should re-lookup and
	// return the user.
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "cred"},
				User:       &proto.UserAuth{Id: "u-1", Email: "discord@example.com"},
			}, nil
		},
		OnCreateUserAuth: func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			return nil, alreadyExistsErr()
		},
	}

	s := &DiscordStrategy{Auth: fake, DiscordId: 1, Email: "discord@example.com"}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "u-1" {
		t.Errorf("user id = %q, want u-1", got.GetId())
	}
}

func TestDiscordStrategyLoginOtherError(t *testing.T) {
	// A non-NotFound error on the lookup should propagate.
	sentinel := errors.New("boom")
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, sentinel
		},
	}

	s := &DiscordStrategy{Auth: fake, DiscordId: 1}
	_, err := s.Login(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

func TestDiscordStrategyLoginNilAuth(t *testing.T) {
	s := &DiscordStrategy{Auth: nil, DiscordId: 1}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when Auth is nil")
	}
}

// ---------- GoogleStrategy ----------

func TestGoogleStrategyLoginExistingUser(t *testing.T) {
	want := &proto.UserAuth{Id: "u-g", Email: "google@example.com"}
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			if in.GetKind() != proto.CredentialKind_CREDENTIAL_KIND_GOOGLE {
				t.Errorf("kind = %v, want GOOGLE", in.GetKind())
			}
			if in.GetGoogleId() != "sub-123" {
				t.Errorf("google_id = %q, want sub-123", in.GetGoogleId())
			}
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "cred-g", UserId: "u-g", Kind: proto.CredentialKind_CREDENTIAL_KIND_GOOGLE},
				User:       want,
			}, nil
		},
		OnCreateUserAuth: func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			t.Fatal("CreateUserAuth should not be called for an existing user")
			return nil, nil
		},
	}

	s := &GoogleStrategy{Auth: fake, GoogleId: "sub-123", Email: "google@example.com", EmailVerified: true}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "u-g" {
		t.Errorf("user id = %q, want u-g", got.GetId())
	}
}

func TestGoogleStrategyLoginCreatesUserAndMarksVerified(t *testing.T) {
	var created *proto.CreateUserAuthRequest
	var updated *proto.UpdateUserAuthRequest
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, notFoundErr()
		},
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			created = in
			return &proto.CreateUserAuthResponse{
				User: &proto.UserAuth{Id: "new-g", Email: in.Email},
			}, nil
		},
		OnUpdateUserAuth: func(in *proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error) {
			updated = in
			return &proto.UpdateUserAuthResponse{User: &proto.UserAuth{Id: in.UserId}}, nil
		},
	}

	s := &GoogleStrategy{Auth: fake, GoogleId: "sub-1", Email: "real@example.com", EmailVerified: true, Username: "Alice"}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "new-g" {
		t.Errorf("user id = %q, want new-g", got.GetId())
	}
	if created == nil {
		t.Fatal("CreateUserAuth was not called")
	}
	if updated == nil {
		t.Fatal("UpdateUserAuth was not called")
	}
	if updated.UserId != "new-g" || updated.RequesterId != "new-g" {
		t.Errorf("UpdateUserAuth user/requester = (%q, %q), want (new-g, new-g)", updated.UserId, updated.RequesterId)
	}
	if updated.EmailVerifiedChange == nil {
		t.Fatal("EmailVerifiedChange was not set")
	}
}

func TestGoogleStrategyLoginVerifiedFalseNoUpdate(t *testing.T) {
	// When EmailVerified is false, the strategy should not call
	// UpdateUserAuth for the verified-at promotion.
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, notFoundErr()
		},
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			return &proto.CreateUserAuthResponse{User: &proto.UserAuth{Id: "new-g", Email: in.Email}}, nil
		},
		OnUpdateUserAuth: func(*proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error) {
			t.Fatal("UpdateUserAuth should not be called when EmailVerified is false")
			return nil, nil
		},
	}

	s := &GoogleStrategy{Auth: fake, GoogleId: "sub-2", Email: "real@example.com", EmailVerified: false}
	if _, err := s.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

func TestGoogleStrategyLoginRequiresGoogleId(t *testing.T) {
	s := &GoogleStrategy{Auth: &FakeAuthClient{}, GoogleId: ""}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error for empty GoogleId")
	}
}

func TestGoogleStrategyLoginNilAuth(t *testing.T) {
	s := &GoogleStrategy{Auth: nil}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when Auth is nil")
	}
}

// ---------- PasswordStrategy ----------

func TestPasswordStrategySignup(t *testing.T) {
	var created *proto.CreateUserAuthRequest
	storedHash := ""
	fake := &FakeAuthClient{
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			created = in
			storedHash = in.PasswordHash
			return &proto.CreateUserAuthResponse{User: &proto.UserAuth{Id: "u-p", Email: in.Email}}, nil
		},
	}

	s := &PasswordStrategy{
		Auth:     fake,
		Hasher:   Argon2Hasher{},
		Email:    "alice@example.com",
		Username: "alice",
		Password: "correct horse battery staple",
		Signup:   true,
	}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "u-p" {
		t.Errorf("user id = %q, want u-p", got.GetId())
	}
	if created == nil {
		t.Fatal("CreateUserAuth was not called")
	}
	if created.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", created.Email)
	}
	if created.Username != "alice" {
		t.Errorf("username = %q, want alice", created.Username)
	}
	if storedHash == "" {
		t.Fatal("password hash was empty")
	}
	if storedHash == "correct horse battery staple" {
		t.Fatal("plaintext password was sent to gRPC")
	}
	// Verify the hash with the hasher.
	ok, err := (Argon2Hasher{}).Verify("correct horse battery staple", storedHash)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify of stored hash returned false")
	}
}

func TestPasswordStrategySignupAlreadyExists(t *testing.T) {
	fake := &FakeAuthClient{
		OnCreateUserAuth: func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			return nil, alreadyExistsErr()
		},
	}
	s := &PasswordStrategy{
		Auth:     fake,
		Hasher:   Argon2Hasher{},
		Email:    "taken@example.com",
		Password: "anything",
		Signup:   true,
	}
	_, err := s.Login(context.Background())
	if !isAlreadyExists(err) {
		t.Fatalf("expected AlreadyExists gRPC error, got %v", err)
	}
}

func TestPasswordStrategySigninSuccess(t *testing.T) {
	hasher := Argon2Hasher{}
	hash, err := hasher.Hash("correctpw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	want := &proto.UserAuth{Id: "u-1", Email: "alice@example.com"}
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			if in.GetKind() != proto.CredentialKind_CREDENTIAL_KIND_PASSWORD {
				t.Errorf("kind = %v, want PASSWORD", in.GetKind())
			}
			if in.GetEmail() != "alice@example.com" {
				t.Errorf("email = %q, want alice@example.com", in.GetEmail())
			}
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "c-1", UserId: "u-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_PASSWORD, Payload: &proto.Credential_PasswordHash{PasswordHash: hash}},
				User:       want,
			}, nil
		},
	}

	s := &PasswordStrategy{
		Auth:     fake,
		Hasher:   hasher,
		Email:    "alice@example.com",
		Password: "correctpw",
	}
	got, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.GetId() != "u-1" {
		t.Errorf("user id = %q, want u-1", got.GetId())
	}
}

func TestPasswordStrategySigninWrongPassword(t *testing.T) {
	hasher := Argon2Hasher{}
	hash, _ := hasher.Hash("correctpw")

	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Payload: &proto.Credential_PasswordHash{PasswordHash: hash}},
				User:       &proto.UserAuth{Id: "u-1"},
			}, nil
		},
	}

	s := &PasswordStrategy{
		Auth:     fake,
		Hasher:   hasher,
		Email:    "alice@example.com",
		Password: "wrongpw",
	}
	_, err := s.Login(context.Background())
	if !errors.Is(err, InvalidCredentialsError) {
		t.Fatalf("expected InvalidCredentialsError, got %v", err)
	}
}

func TestPasswordStrategySigninUserNotFound(t *testing.T) {
	// When the user doesn't exist, the strategy should still do a
	// dummy verify to keep timing constant, and return
	// InvalidCredentialsError (no leak about whether the email exists).
	fake := &FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, notFoundErr()
		},
	}

	s := &PasswordStrategy{
		Auth:     fake,
		Hasher:   Argon2Hasher{},
		Email:    "ghost@example.com",
		Password: "anything",
	}
	_, err := s.Login(context.Background())
	if !errors.Is(err, InvalidCredentialsError) {
		t.Fatalf("expected InvalidCredentialsError, got %v", err)
	}
}

func TestPasswordStrategySigninEmptyEmail(t *testing.T) {
	// Both hidden from the /auth/login endpoint and the strategy
	// itself: empty email is invalidated to avoid leaking whether
	// the field was even supplied.
	s := &PasswordStrategy{
		Auth:     &FakeAuthClient{},
		Hasher:   Argon2Hasher{},
		Email:    "",
		Password: "x",
	}
	if _, err := s.Login(context.Background()); !errors.Is(err, InvalidCredentialsError) {
		t.Fatalf("expected InvalidCredentialsError, got %v", err)
	}
}

func TestPasswordStrategyNilAuth(t *testing.T) {
	s := &PasswordStrategy{
		Auth:     nil,
		Hasher:   Argon2Hasher{},
		Email:    "a@b.c",
		Password: "x",
	}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when Auth is nil")
	}
}

func TestPasswordStrategyNilHasher(t *testing.T) {
	s := &PasswordStrategy{
		Auth:     &FakeAuthClient{},
		Hasher:   nil,
		Email:    "a@b.c",
		Password: "x",
	}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when Hasher is nil")
	}
}

// ---------- PasskeyLoginStrategy ----------

func TestPasskeyLoginStrategyMissingFields(t *testing.T) {
	s := &PasskeyLoginStrategy{Auth: &FakeAuthClient{}}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when ceremony fields are missing")
	}
}

func TestPasskeyLoginStrategyNilAuth(t *testing.T) {
	s := &PasskeyLoginStrategy{
		Auth:              nil,
		CredentialId:      []byte("cred"),
		ClientDataJSON:    []byte("cd"),
		AuthenticatorData: []byte("ad"),
		Signature:         []byte("sig"),
	}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when Auth is nil")
	}
}

// ---------- PasskeyRegisterStrategy ----------

func TestPasskeyRegisterStrategyMissingFields(t *testing.T) {
	s := &PasskeyRegisterStrategy{Auth: &FakeAuthClient{}}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when UserId/RequesterId missing")
	}
}

func TestPasskeyRegisterStrategyMissingCredentials(t *testing.T) {
	s := &PasskeyRegisterStrategy{
		Auth:         &FakeAuthClient{},
		UserId:       "u-1",
		RequesterId:  "u-1",
		CredentialId: nil,
		PublicKey:    nil,
	}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when credential_id/public_key missing")
	}
}

func TestPasskeyRegisterStrategyNilAuth(t *testing.T) {
	s := &PasskeyRegisterStrategy{
		Auth:         nil,
		UserId:       "u-1",
		RequesterId:  "u-1",
		CredentialId: []byte("c"),
		PublicKey:    []byte("pk"),
	}
	if _, err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error when Auth is nil")
	}
}

// ---------- helpers ----------

// notFoundErr returns a gRPC-style NotFound status error.
func notFoundErr() error {
	return status.Error(codes.NotFound, "not found")
}

// alreadyExistsErr returns a gRPC-style AlreadyExists status error.
func alreadyExistsErr() error {
	return status.Error(codes.AlreadyExists, "already exists")
}
