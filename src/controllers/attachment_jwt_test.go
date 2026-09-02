package controllers

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/golang-jwt/jwt/v5"
)

// signAttachmentJWT builds a token with the shape the gRPC backend mints:
// iss="WerSu gRPC", sub=userID, att=attachmentID, iat=now, exp=now+ttl.
// It is shared by every test case so we never hand-roll tokens ad-hoc.
func signAttachmentJWT(t *testing.T, secret, issuer, userID, att string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := utils.AttachmentAccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Att: att,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}

func TestUnpackAttachmentJWT_Valid(t *testing.T) {
	secret := "test-secret"
	att := "attachments/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"
	tok := signAttachmentJWT(t, secret, utils.AttachmentJWTIssuer, "user-1", att, time.Minute)

	claims, code, err := utils.UnpackAttachmentJWT(tok, secret)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("expected subject user-1, got %q", claims.Subject)
	}
	if claims.Att != att {
		t.Fatalf("expected att %q, got %q", att, claims.Att)
	}
}

func TestUnpackAttachmentJWT_WrongIssuer(t *testing.T) {
	secret := "test-secret"
	tok := signAttachmentJWT(t, secret, "wersu-rest-proxy", "user-1", "att-1", time.Minute)

	_, code, err := utils.UnpackAttachmentJWT(tok, secret)
	if err == nil {
		t.Fatalf("expected error for wrong issuer, got nil")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", code)
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected error to mention issuer, got %q", err.Error())
	}
}

func TestUnpackAttachmentJWT_WrongSignature(t *testing.T) {
	tok := signAttachmentJWT(t, "signer-secret", utils.AttachmentJWTIssuer, "user-1", "att-1", time.Minute)

	_, code, err := utils.UnpackAttachmentJWT(tok, "verifier-secret")
	if err == nil {
		t.Fatalf("expected error for bad signature, got nil")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", code)
	}
}

func TestUnpackAttachmentJWT_Expired(t *testing.T) {
	secret := "test-secret"
	// negative ttl -> exp in the past
	tok := signAttachmentJWT(t, secret, utils.AttachmentJWTIssuer, "user-1", "att-1", -time.Minute)

	_, code, err := utils.UnpackAttachmentJWT(tok, secret)
	if err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", code)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected error to mention expiry, got %q", err.Error())
	}
}

func TestUnpackAttachmentJWT_Malformed(t *testing.T) {
	_, code, err := utils.UnpackAttachmentJWT("not.a.jwt", "irrelevant")
	if err == nil {
		t.Fatalf("expected error for malformed token, got nil")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", code)
	}
}

func TestUnpackAttachmentJWT_MissingSub(t *testing.T) {
	secret := "test-secret"
	tok := signAttachmentJWT(t, secret, utils.AttachmentJWTIssuer, "", "att-1", time.Minute)

	_, code, err := utils.UnpackAttachmentJWT(tok, secret)
	if err == nil {
		t.Fatalf("expected error for missing sub, got nil")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", code)
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Fatalf("expected error to mention sub, got %q", err.Error())
	}
}

func TestUnpackAttachmentJWT_MissingAtt(t *testing.T) {
	secret := "test-secret"
	tok := signAttachmentJWT(t, secret, utils.AttachmentJWTIssuer, "user-1", "", time.Minute)

	_, code, err := utils.UnpackAttachmentJWT(tok, secret)
	if err == nil {
		t.Fatalf("expected error for missing att, got nil")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", code)
	}
	if !strings.Contains(err.Error(), "att") {
		t.Fatalf("expected error to mention att, got %q", err.Error())
	}
}

func TestAttachmentAccessClaims_Roundtrip(t *testing.T) {
	// Pins the wire shape the gRPC backend mints. If this drifts, the test
	// catches it without needing the live backend.
	secret := "roundtrip-secret"
	att := "attachments/some-key"
	tok := signAttachmentJWT(t, secret, utils.AttachmentJWTIssuer, "user-42", att, time.Hour)

	claims, _, err := utils.UnpackAttachmentJWT(tok, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-42" {
		t.Fatalf("subject mismatch: %q", claims.Subject)
	}
	if claims.Att != att {
		t.Fatalf("att mismatch: %q", claims.Att)
	}
	if claims.Issuer != utils.AttachmentJWTIssuer {
		t.Fatalf("issuer mismatch: %q", claims.Issuer)
	}
}

func TestLooksLikeJWT(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"not-a-jwt", false},
		{"only.two", false},
		{"a.b.c.d", false},
		{".b.c", false},
		{"a..c", false},
		{"a.b.", false},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.signature", true},
	}
	for _, tc := range cases {
		if got := looksLikeJWT(tc.in); got != tc.want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
