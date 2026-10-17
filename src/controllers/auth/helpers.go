package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

// withRequestBodyJSON replaces `c.Request.Body` with a reader over
// the JSON encoding of `v`. The previous body (which contained the
// SPA's wrapper including `session_key` / `friendly_name`) is
// discarded; go-webauthn then parses the lib-shaped credential
// exactly as if it had been posted at the top level.
func withRequestBodyJSON(c *gin.Context, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(b))
	c.Request.ContentLength = int64(len(b))
	return nil
}

// validateCeremonyCredential does an early-shape sanity check on the
// SPA's nested credential. Returns the first user-visible error.
// The library's own parser will fail with `Parse error for
// Registration` / `Parse error for Assertion` if these are off, but
// catching them up-front lets the controller return 400 with a more
// specific message rather than 401 from `FinishRegistration`.
func validateCeremonyCredential(cred PasskeyFinishCredential) error {
	if cred.Type != "" && cred.Type != "public-key" {
		return errors.New("credential.type must be \"public-key\"")
	}
	if cred.ID == "" {
		return errors.New("credential.id is required")
	}
	if cred.RawID == "" {
		return errors.New("credential.rawId is required")
	}
	if cred.Response.ClientDataJSON == "" {
		return errors.New("credential.response.clientDataJSON is required")
	}
	return nil
}

// authTransports converts the typed webauthn transport list back to
// strings for the gRPC `repeated string` field.
func authTransports(in []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

// ceremonyOptionsJSON round-trips a webauthn options struct through
// encoding/json so gin's encoder can serialize it generically.
func ceremonyOptionsJSON(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// beginReplyFrom wraps the ceremony envelope plus session key in a
// PasskeyCeremonyBeginReply. `challenge` is also lifted to the top
// level so a caller that reads `data.challenge` directly finds it.
func beginReplyFrom(key string, response any) PasskeyCeremonyBeginReply {
	opts := ceremonyOptionsJSON(response)
	challenge, _ := opts["challenge"].(string)
	return PasskeyCeremonyBeginReply{
		SessionKey: key,
		Challenge:  challenge,
		Options:    opts,
	}
}

// withLinkUser adds the cache-bypass user fields populated by
// /auth/link/passkey/begin. Other /begin endpoints leave them empty.
func withLinkUser(reply PasskeyCeremonyBeginReply, userID, userName string) PasskeyCeremonyBeginReply {
	reply.UserID = base64.RawURLEncoding.EncodeToString([]byte(userID))
	reply.UserName = userName
	return reply
}
