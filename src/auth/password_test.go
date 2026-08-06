package auth

import (
	"testing"
)

// TestArgon2HashAndVerify round-trips a password through the hasher.
func TestArgon2HashAndVerify(t *testing.T) {
	hasher := Argon2Hasher{}
	plain := "correcthorsebatterystaple"
	hash, err := hasher.Hash(plain)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash == "" {
		t.Fatal("Hash returned empty string")
	}
	ok, err := hasher.Verify(plain, hash)
	if err != nil {
		t.Fatalf("Verify correct: %v", err)
	}
	if !ok {
		t.Fatal("Verify correct returned false")
	}
	ok, err = hasher.Verify("wrong", hash)
	if err != nil {
		t.Fatalf("Verify wrong: %v", err)
	}
	if ok {
		t.Fatal("Verify wrong returned true")
	}
}

// TestArgon2VerifyRejectsBadEncoding verifies the verify path
// rejects malformed encoded hashes.
func TestArgon2VerifyRejectsBadEncoding(t *testing.T) {
	if _, err := (Argon2Hasher{}).Verify("anything", "not-a-phc-string"); err == nil {
		t.Fatal("expected error for malformed hash")
	}
}

// TestArgon2HashRejectsEmpty verifies the hash path rejects empty
// plaintext.
func TestArgon2HashRejectsEmpty(t *testing.T) {
	if _, err := (Argon2Hasher{}).Hash(""); err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

// TestPHCEncodeDecode round-trips a PHC string.
func TestPHCEncodeDecode(t *testing.T) {
	salt := []byte("0123456789abcdef")
	wantHash := []byte("fedcba9876543210")
	encoded := EncodePHC("argon2id", 19, 64*1024, 3, 4, salt, wantHash)
	mode, version, m, time, p, gotSalt, gotHash, err := DecodePHC(encoded)
	if err != nil {
		t.Fatalf("DecodePHC: %v", err)
	}
	if mode != "argon2id" {
		t.Errorf("mode = %q, want argon2id", mode)
	}
	if version != 19 {
		t.Errorf("version = %d, want 19", version)
	}
	if m != 64*1024 || time != 3 || p != 4 {
		t.Errorf("params = (m=%d, t=%d, p=%d), want (65536, 3, 4)", m, time, p)
	}
	if string(gotSalt) != string(salt) {
		t.Errorf("salt mismatch")
	}
	if string(gotHash) != string(wantHash) {
		t.Errorf("hash mismatch")
	}
}
