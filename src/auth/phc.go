package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// randomBytes returns n cryptographically-random bytes. Used for the
// salt and (if needed) dummy inputs.
func randomBytes(n uint32) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// EncodePHC builds a PHC string for argon2id. The format is the
// modular crypt string documented by the PHC spec:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
//
// The salt and hash are base64-encoded without padding, matching the
// argon2 reference implementation.
func EncodePHC(mode string, version int, m, t uint32, p uint8, salt, hash []byte) string {
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		mode, version, m, t, p, saltB64, hashB64)
}

// DecodePHC parses a PHC string back into its components. Returns
// (mode, version, m, t, p, salt, hash, error).
func DecodePHC(s string) (string, int, uint32, uint32, uint8, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid PHC string (segments=%d)", len(parts))
	}
	mode := parts[1]
	// parts[2] is "v=19"
	if !strings.HasPrefix(parts[2], "v=") {
		return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid PHC version segment: %q", parts[2])
	}
	version, err := strconv.Atoi(parts[2][2:])
	if err != nil {
		return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid PHC version: %w", err)
	}
	// parts[3] is "m=65536,t=3,p=4"
	var m, t uint32
	var p uint8
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid PHC param: %q", kv)
		}
		switch k {
		case "m":
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid m=: %w", err)
			}
			m = uint32(n)
		case "t":
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid t=: %w", err)
			}
			t = uint32(n)
		case "p":
			n, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid p=: %w", err)
			}
			p = uint8(n)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid PHC salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return "", 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid PHC hash: %w", err)
	}
	return mode, version, m, t, p, salt, hash, nil
}

// constantTimeEqual reports whether a and b are equal in constant
// time. Used to compare the recomputed argon2 hash against the
// stored hash so a successful verify doesn't leak ratio information.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
