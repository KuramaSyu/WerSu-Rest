package auth

// Regression pin: the SPA in `WerSu-Frontend` posts the resolved
// `PublicKeyCredential` nested under `credential`, with binary
// fields base64url-no-pad per `expectBase64UrlNoPad`. The backend
// must (1) accept that wire shape on bind, (2) validate the
// resolved nested credential up-front, and (3) round-trip the
// `credential` payload into the lib-shaped HTTP body that
// `webauthn.FinishRegistration` parses (the previous failure mode
// was `Parse error for Registration`).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestFinishBodyShape_AcceptsNestedCredential(t *testing.T) {
	// The request body the SPA produces should bind cleanly into
	// PasskeyCeremonyFinishRequest: nested `credential`,
	// base64url rawId/clientDataJSON/attestationObject, optional
	// transports list, optional friendly_name.
	body := []byte(`{
	  "session_key": "sk_test",
	  "friendly_name": "iPhone",
	  "credential": {
	    "id": "Y3JlZC1pZA",
	    "rawId": "Y3JlZC1pZA",
	    "type": "public-key",
	    "response": {
	      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
	      "attestationObject": "o2NmbXRkbm9uZWA",
	      "transports": ["internal"]
	    },
	    "clientExtensionResults": {}
	  }
	}`)
	var req PasskeyCeremonyFinishRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.SessionKey != "sk_test" {
		t.Errorf("SessionKey = %q, want sk_test", req.SessionKey)
	}
	if req.FriendlyName != "iPhone" {
		t.Errorf("FriendlyName = %q, want iPhone", req.FriendlyName)
	}
	if req.Credential.ID != "Y3JlZC1pZA" {
		t.Errorf("Credential.ID = %q", req.Credential.ID)
	}
	if req.Credential.Type != "public-key" {
		t.Errorf("Credential.Type = %q, want public-key", req.Credential.Type)
	}
	if req.Credential.Response.ClientDataJSON == "" {
		t.Errorf("ClientDataJSON empty")
	}
	if req.Credential.Response.AttestationObject == "" {
		t.Errorf("AttestationObject empty")
	}
	if len(req.Credential.Response.Transports) != 1 || req.Credential.Response.Transports[0] != "internal" {
		t.Errorf("Transports = %v, want [internal]", req.Credential.Response.Transports)
	}
}

func TestFinishBodyShape_AssertionOmitsAttestationFields(t *testing.T) {
	// Login path: assertion-shaped credential carries
	// authenticatorData + signature (+ optional userHandle). The
	// struct must accept that without requiring attestationObject
	// / transports.
	body := []byte(`{
	  "session_key": "sk_test",
	  "credential": {
	    "id": "Y3JlZC1pZA",
	    "rawId": "Y3JlZC1pZA",
	    "type": "public-key",
	    "response": {
	      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
	      "authenticatorData": "Y3J4eHRzWQ",
	      "signature": "MEUCIQDxY3VyZUNpZFNpZ19f"
	    },
	    "clientExtensionResults": {}
	  }
	}`)
	var req PasskeyCeremonyFinishRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Credential.Response.AttestationObject != "" {
		t.Errorf("AttestationObject should be empty on assertion, got %q", req.Credential.Response.AttestationObject)
	}
	if req.Credential.Response.AuthenticatorData == "" {
		t.Errorf("AuthenticatorData empty")
	}
	if req.Credential.Response.Signature == "" {
		t.Errorf("Signature empty")
	}
	if req.Credential.Response.UserHandle != "" {
		t.Errorf("UserHandle = %q, want empty when null", req.Credential.Response.UserHandle)
	}
}

func TestValidateCeremonyCredential_RejectsMissingFields(t *testing.T) {
	tests := []struct {
		name string
		cred PasskeyFinishCredential
		want string
	}{
		{
			name: "wrong type",
			cred: PasskeyFinishCredential{Type: "magic-link", ID: "x", RawID: "x",
				Response: PasskeyFinishResp{ClientDataJSON: "x"}},
			want: "credential.type must be",
		},
		{
			name: "missing id",
			cred: PasskeyFinishCredential{Type: "public-key", RawID: "x",
				Response: PasskeyFinishResp{ClientDataJSON: "x"}},
			want: "credential.id is required",
		},
		{
			name: "missing rawId",
			cred: PasskeyFinishCredential{Type: "public-key", ID: "x",
				Response: PasskeyFinishResp{ClientDataJSON: "x"}},
			want: "credential.rawId is required",
		},
		{
			name: "missing clientDataJSON",
			cred: PasskeyFinishCredential{Type: "public-key", ID: "x", RawID: "x",
				Response: PasskeyFinishResp{}},
			want: "clientDataJSON is required",
		},
		{
			name: "valid passes",
			cred: PasskeyFinishCredential{Type: "public-key", ID: "x", RawID: "x",
				Response: PasskeyFinishResp{ClientDataJSON: "x"}},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCeremonyCredential(tc.cred)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestWithRequestBodyJSON_RewritesRequestBody(t *testing.T) {
	// After withRequestBodyJSON(c, v), c.Request.Body must yield
	// exactly json.Marshal(v) regardless of the original body.
	c := newPasskeyTestGinContext(t, `{"session_key":"x","foo":"discarded"}`)
	in := map[string]any{
		"id":    "Y3JlZA",
		"rawId": "Y3JlZA",
		"type":  "public-key",
		"foo":   "kept",
	}
	if err := withRequestBodyJSON(c, in); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(got, []byte(`"foo":"kept"`)) {
		t.Errorf("new body missing foo: %s", got)
	}
	if bytes.Contains(got, []byte(`"session_key"`)) {
		t.Errorf("new body still carries the wrapper: %s", got)
	}
	if c.Request.ContentLength <= 0 {
		t.Errorf("ContentLength = %d, want > 0", c.Request.ContentLength)
	}
}

func TestTakeCeremonyRegression_PinExpiryMessage(t *testing.T) {
	// Pin the body of the "expired" path so the structured error
	// we emit cannot regress to a generic string without breaking
	// this test.
	ac := &AuthController{}
	ac.ceremonyStore.Store("k", ceremonyEntry{
		data:    webauthn.SessionData{},
		expires: time.Now().Add(-time.Minute),
	})
	_, err := ac.takeCeremony("k")
	if err == nil {
		t.Fatalf("expected expired error")
	}
	if !strings.Contains(err.Error(), "ceremony expired at") {
		t.Errorf("error = %q, want 'ceremony expired at ...'", err.Error())
	}
}

func newPasskeyTestGinContext(t *testing.T, rawBody string) *gin.Context {
	t.Helper()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(rawBody))
	return c
}
