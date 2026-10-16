package auth

import (
	"context"
	"errors"

	"golang.org/x/crypto/argon2"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// Argon2id parameters. OWASP 2024 recommendation for argon2id:
// memory=64 MiB, iterations=3, parallelism=4, salt=16 bytes, hash=32 bytes.
// Tune m upward on production hardware if login latency is fine.
const (
	argonMemory      uint32 = 64 * 1024 // 64 MiB
	argonIterations  uint32 = 3
	argonParallelism uint8  = 4
	argonSaltLen     uint32 = 16
	argonHashLen     uint32 = 32
)

// Argon2Hasher is the server-side helper that hashes plaintext
// passwords into the PHC-encoded argon2id string the gRPC backend
// stores. Clients send plaintext over the wire; the server hashes
// before reaching gRPC.
//
// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
type Argon2Hasher struct{}

// Hash returns a PHC-encoded argon2id hash of plaintext. Empty
// input is rejected so trivial passwords never reach the store.
func (Argon2Hasher) Hash(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("empty password")
	}
	salt := randomBytes(argonSaltLen)
	hash := argon2.IDKey([]byte(plaintext), salt, argonIterations, argonMemory, argonParallelism, argonHashLen)
	return EncodePHC("argon2id", argon2.Version, argonMemory, argonIterations, argonParallelism, salt, hash), nil
}

// Verify recomputes the hash from the encoded PHC string and
// constant-time compares it. Kept for tests and future server-side
// re-verification flows.
func (Argon2Hasher) Verify(plaintext, encoded string) (bool, error) {
	mode, _, m, t, p, salt, want, err := DecodePHC(encoded)
	if err != nil {
		return false, err
	}
	if mode != "argon2id" {
		return false, errors.New("unsupported hash mode: " + mode)
	}
	got := argon2.IDKey([]byte(plaintext), salt, t, m, p, uint32(len(want)))
	return constantTimeEqual(got, want), nil
}

// PasswordStrategy is the dual-purpose strategy for password auth.
// Clients send plaintext; the strategy hashes before reaching gRPC.
//
// Signup=false: look up the user by email, hash the submitted
// plaintext, constant-time-compare against the stored hash. Returns
// InvalidCredentials on any mismatch. Signup=true: hash the
// plaintext, create the user with the resulting hash.
type PasswordStrategy struct {
	Auth      AuthServiceClientIface
	Email     string
	Password  string // plaintext; hashed by the strategy before gRPC
	Username  string // signup only
	Signup    bool
	AvatarUrl string
}

// InvalidCredentialsError is returned by password login when the
// email doesn't exist or the hash doesn't match.
var InvalidCredentialsError = errors.New("invalid email or password")

// Login implements LoginStrategy. For signup, it calls CreateUserAuth
// with the strategy-hashed plaintext. For signin, it looks up the
// user by email and constant-time-compares the hashed plaintext
// against the stored hash.
func (s *PasswordStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}
	if s.Email == "" || s.Password == "" {
		return nil, InvalidCredentialsError
	}

	if s.Signup {
		return s.signup(ctx)
	}
	return s.signin(ctx)
}

func (s *PasswordStrategy) signup(ctx context.Context) (*proto.UserAuth, error) {
	hash, err := (Argon2Hasher{}).Hash(s.Password)
	if err != nil {
		return nil, err
	}
	createResp, err := s.Auth.CreateUserAuth(ctx, &proto.CreateUserAuthRequest{
		Email:        s.Email,
		Username:     s.Username,
		PasswordHash: hash,
		AvatarUrl:    s.AvatarUrl,
	})
	if err != nil {
		// ALREADY_EXISTS on the email is a conflict that the
		// controller should report as 409 email taken.
		return nil, err
	}
	return createResp.GetUser(), nil
}

func (s *PasswordStrategy) signin(ctx context.Context) (*proto.UserAuth, error) {
	resp, err := s.Auth.FindCredentialByProvider(ctx, &proto.FindCredentialByProviderRequest{
		Kind:       proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Identifier: &proto.FindCredentialByProviderRequest_Email{Email: s.Email},
	})
	if err != nil {
		if IsNotFound(err) {
			// No user with this email -- still hash against the
			// submitted plaintext to keep timing on par with a real
			// compare (no leak of existence).
			_, _ = (Argon2Hasher{}).Hash(s.Password)
			return nil, InvalidCredentialsError
		}
		return nil, err
	}
	stored := resp.GetCredential().GetPasswordHash()
	ok, verr := (Argon2Hasher{}).Verify(s.Password, stored)
	if verr != nil || !ok {
		return nil, InvalidCredentialsError
	}
	return resp.GetUser(), nil
}