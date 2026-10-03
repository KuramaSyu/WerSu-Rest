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

// Argon2Hasher is the small client-side helper that produces the
// PHC-encoded argon2id hash the REST API accepts. The REST server
// never hashes itself; clients send the hash directly.
type Argon2Hasher struct{}

// Hash returns a PHC-encoded argon2id hash of plaintext.
// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
func (Argon2Hasher) Hash(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("empty password")
	}
	salt := randomBytes(argonSaltLen)
	hash := argon2.IDKey([]byte(plaintext), salt, argonIterations, argonMemory, argonParallelism, argonHashLen)
	return EncodePHC("argon2id", argon2.Version, argonMemory, argonIterations, argonParallelism, salt, hash), nil
}

// Verify recomputes the hash from the encoded PHC string and
// constant-time compares it. Kept for client-side flows and tests;
// the server never calls it.
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
// The REST API never sees plaintext: the client sends a precomputed
// PHC-encoded hash and the server treats it as opaque bytes.
// Signup=false: look up the user by email and string-compare the
// submitted hash against the stored hash. Returns InvalidCredentials
// on any mismatch. Signup=true: create the user with the supplied
// hash as-is.
type PasswordStrategy struct {
	Auth      AuthServiceClientIface
	Email     string
	Hash      string
	Algorithm string // must be argon2id when set; the prefix is also checked
	Username  string // signup only
	Signup    bool
	AvatarUrl string
}

// InvalidCredentialsError is returned by password login when the
// email doesn't exist or the hash doesn't match.
var InvalidCredentialsError = errors.New("invalid email or password")

// Login implements LoginStrategy. For signup, it calls CreateUserAuth
// with the client-provided hash. For signin, it looks up the user
// by email and constant-time-compares against the stored hash.
func (s *PasswordStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}
	if s.Email == "" || !ValidatePasswordHash(s.Hash, s.Algorithm) {
		return nil, InvalidCredentialsError
	}

	if s.Signup {
		return s.signup(ctx)
	}
	return s.signin(ctx)
}

func (s *PasswordStrategy) signup(ctx context.Context) (*proto.UserAuth, error) {
	createResp, err := s.Auth.CreateUserAuth(ctx, &proto.CreateUserAuthRequest{
		Email:        s.Email,
		Username:     s.Username,
		PasswordHash: s.Hash,
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
			// No user with this email -- do a dummy compare to keep
			// timing on par with a real one (no leak of existence).
			constantTimeEqual([]byte(s.Hash), []byte(s.Hash))
			return nil, InvalidCredentialsError
		}
		return nil, err
	}
	stored := resp.GetCredential().GetPasswordHash()
	if !constantTimeEqual([]byte(s.Hash), []byte(stored)) {
		return nil, InvalidCredentialsError
	}
	return resp.GetUser(), nil
}
