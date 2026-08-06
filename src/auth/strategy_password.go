package auth

import (
	"context"
	"errors"

	"golang.org/x/crypto/argon2"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// Argon2id parameters. OWASP 2024 recommendation for argon2id:
// memory=64 MiB, iterations=3, parallelism=4, salt=16 bytes, hash=32 bytes.
// Tune `m` upward on production hardware if login latency is fine.
const (
	argonMemory      uint32 = 64 * 1024 // 64 MiB
	argonIterations  uint32 = 3
	argonParallelism uint8  = 4
	argonSaltLen     uint32 = 16
	argonHashLen     uint32 = 32
)

// PasswordHasher is the small surface a PasswordStrategy needs to
// hash and verify passwords. The argon2 module is the default impl.
type PasswordHasher interface {
	Hash(plaintext string) (string, error)
	Verify(plaintext, encoded string) (bool, error)
}

// Argon2Hasher implements PasswordHasher using argon2id. The encoded
// hash follows the PHC string format (modular crypt) so the
// parameters travel with the hash and can be tuned without breaking
// existing rows.
type Argon2Hasher struct{}

// Hash returns a PHC-encoded argon2id hash of plaintext.
//
// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
func (Argon2Hasher) Hash(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("empty password")
	}
	salt := randomBytes(argonSaltLen)
	hash := argon2.IDKey([]byte(plaintext), salt, argonIterations, argonMemory, argonParallelism, argonHashLen)
	return EncodePHC("argon2id", argon2.Version, argonMemory, argonIterations, argonParallelism, salt, hash), nil
}

// Verify recomputes the hash with the salt and parameters from the
// encoded string and constant-time compares the result.
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
// It is constructed with the email and plaintext password. The
// `Signup` field switches between:
//   - Signup=false (default): look up the user by email and verify
//     the password against the stored hash. Returns InvalidCredentials
//     on any mismatch (no leak of which side failed).
//   - Signup=true: create a new user with the hashed password. The
//     email must not yet exist.
type PasswordStrategy struct {
	Auth     AuthServiceClientIface
	Hasher   PasswordHasher
	Email    string
	Password string
	Username string // only used during signup
	Signup   bool

	// AvatarUrl is the resolved absolute URL to the user's avatar.
	// The controller fills it (typically via Gravatar fallback based
	// on Email) and the strategy propagates it on signup.
	AvatarUrl string
}

// InvalidCredentialsError is returned by password login when the
// email doesn't exist or the password doesn't match. The controller
// maps it to a generic 401 with the "invalid email or password"
// message that doesn't leak which side failed.
var InvalidCredentialsError = errors.New("invalid email or password")

// Login implements LoginStrategy. For signup, it calls CreateUserAuth
// then links the password credential. For signin, it looks up the
// user by email and verifies the password.
func (s *PasswordStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}
	if s.Email == "" {
		return nil, InvalidCredentialsError
	}
	if s.Hasher == nil {
		return nil, errors.New("password hasher not configured")
	}

	if s.Signup {
		return s.signup(ctx)
	}
	return s.signin(ctx)
}

func (s *PasswordStrategy) signup(ctx context.Context) (*proto.UserAuth, error) {
	hash, err := s.Hasher.Hash(s.Password)
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
		// controller should report to the user as "email taken".
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
		if isNotFound(err) {
			// No user with this email -- constant-time dummy verify
			// to prevent timing leaks about which emails are
			// registered.
			_, _ = s.Hasher.Verify(s.Password, dummyEncodedHash())
			return nil, InvalidCredentialsError
		}
		return nil, err
	}

	ok, err := s.Hasher.Verify(s.Password, resp.GetCredential().GetPasswordHash())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, InvalidCredentialsError
	}
	return resp.GetUser(), nil
}

// dummyEncodedHash is a valid-shaped argon2id hash used to keep the
// verify path constant-time when the user doesn't exist. The
// plaintext is irrelevant; we just want the verify to take the same
// time as a real one.
func dummyEncodedHash() string {
	return "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
