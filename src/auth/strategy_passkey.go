package auth

import (
	"context"
	"errors"

	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

// PasskeyRegisterStrategy persists a new passkey for the
// authenticated user. The gRPC backend does no WebAuthn ceremony
// validation here -- the controller has already verified the
// attestation via the WebAuthn ceremony (challenge, origin, RP ID,
// attestation signature) and the resulting (credential_id, public_key)
// is opaque to the backend. The backend stores it.
//
// The strategy is invoked from POST /api/auth/passkey/register/finish
// after the browser has signed the challenge.
type PasskeyRegisterStrategy struct {
	Auth        AuthServiceClientIface
	UserId      string
	RequesterId string

	// Outputs from the WebAuthn ceremony (passed through):
	CredentialId   []byte
	PublicKey      []byte
	Transports     []string
	Aaguid         []byte
	BackupEligible bool
	BackupState    bool
	UserVerified   bool
	FriendlyName   string
}

// Login implements LoginStrategy. For registration, success is
// the registration record being persisted -- since the user is
// already authenticated, the returned UserAuth is the same one
// they came in with.
func (s *PasskeyRegisterStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}
	if s.UserId == "" || s.RequesterId == "" {
		return nil, errors.New("passkey register requires user and requester ids")
	}
	if s.CredentialId == nil || s.PublicKey == nil {
		return nil, errors.New("passkey register requires credential_id and public_key")
	}

	resp, err := s.Auth.RegisterPasskey(ctx, &proto.RegisterPasskeyRequest{
		UserId:         s.UserId,
		RequesterId:    s.RequesterId,
		CredentialId:   s.CredentialId,
		PublicKey:      s.PublicKey,
		Transports:     s.Transports,
		Aaguid:         s.Aaguid,
		BackupEligible: s.BackupEligible,
		BackupState:    s.BackupState,
		UserVerified:   s.UserVerified,
		FriendlyName:   s.FriendlyName,
	})
	if err != nil {
		return nil, err
	}

	// The strategy returns the user that owns the passkey. The
	// caller (controller) is responsible for issuing a JWT.
	userId := resp.GetPasskey().GetUserId()
	userResp, err := s.Auth.GetUserAuth(ctx, &proto.GetUserAuthRequest{
		Identifier: &proto.GetUserAuthRequest_UserId{UserId: userId},
	})
	if err != nil {
		return nil, err
	}
	return userResp.GetUser(), nil
}

// PasskeyLoginStrategy validates a WebAuthn assertion and returns the
// authenticated user. The controller has already extracted the
// (credential_id, client_data, authenticator_data, signature) from
// the browser's navigator.credentials.get() result. The strategy
// delegates verification to the gRPC backend and persists the new
// sign counter.
//
// Per the design: the gRPC backend owns the WebAuthn ceremony
// verification (the public key + the COSE signature check). The
// gRPC side will expose a `VerifyPasskey` RPC that takes the
// (credential_id, client_data, authenticator_data, signature) blob
// and returns OK or FAILED_PRECONDITION. The strategy here is a
// thin pre/post orchestrator -- it strips the type-related concerns
// (the lookup, the counter bump) and leaves the crypto to the
// backend.
type PasskeyLoginStrategy struct {
	Auth AuthServiceClientIface

	// Outputs from the WebAuthn ceremony (passed through):
	CredentialId      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
}

// InvalidPasskeyError is returned when the gRPC backend rejects the
// assertion signature, the sign counter is not monotonic, or the
// passkey has been revoked.
var InvalidPasskeyError = errors.New("invalid passkey")

// Login implements LoginStrategy.
func (s *PasskeyLoginStrategy) Login(ctx context.Context) (*proto.UserAuth, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not configured")
	}
	if s.CredentialId == nil || s.ClientDataJSON == nil || s.AuthenticatorData == nil || s.Signature == nil {
		return nil, errors.New("passkey login requires credential_id, client_data, authenticator_data, signature")
	}

	// 1. Look up the passkey by credential_id. The user is the
	// owner of the credential row.
	resp, err := s.Auth.FindPasskey(ctx, &proto.FindPasskeyRequest{
		CredentialId: s.CredentialId,
	})
	if err != nil {
		return nil, err
	}
	_ = resp.GetPasskey() // referenced by the post-RPC code below

	// 2. Verify the assertion signature against the stored public
	// key. The gRPC backend owns this check. When the dedicated
	// `VerifyPasskey` RPC is wired up, this is the call site.
	//
	// For now, the simplest correct behavior is to require a new
	// `VerifyPasskey` RPC that takes the four byte slices and
	// returns the updated passkey. A FAILED_PRECONDITION means the
	// signature didn't verify or the counter went backwards.
	//
	// Until the RPC exists, surface a clear error rather than a
	// silent fallback that would let an attacker bypass the check.
	return nil, errors.New("passkey login requires VerifyPasskey RPC; not yet implemented on the gRPC backend")

	// The following lines are unreachable today but document the
	// intended post-RPC flow:
	//
	//   // 3. Bump the sign counter. The backend enforces the
	//   // strictly-greater check; a FAILED_PRECONDITION here means
	//   // another concurrent login already won the race.
	//   _, _ = s.Auth.UpdatePasskeyCounter(ctx, &proto.UpdatePasskeyCounterRequest{
	//       PasskeyId:    passkey.GetId(),
	//       NewSignCount: passkey.GetSignCount() + 1,
	//   })
	//
	//   // 4. Look up the user that owns the passkey.
	//   userResp, err := s.Auth.GetUserAuth(ctx, &proto.GetUserAuthRequest{
	//       Identifier: &proto.GetUserAuthRequest_UserId{UserId: passkey.GetUserId()},
	//   })
	//   if err != nil {
	//       return nil, err
	//   }
	//   return userResp.GetUser(), nil
}
