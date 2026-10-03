package auth

import "strings"

// SupportedPasswordAlgorithm is the only algorithm the server accepts
// for password hashes. PHC strings encode the algorithm in their
// prefix, so this constant doubles as the PHC prefix check.
const SupportedPasswordAlgorithm = "argon2id"

// passwordHashPrefix is the PHC magic that every accepted hash must
// carry. Kept private; callers use ValidatePasswordHash instead.
const passwordHashPrefix = "$argon2id$"

// ValidatePasswordHash enforces that the submitted hash is a
// structurally valid PHC-encoded SupportedPasswordAlgorithm string
// and that the declared algorithm (if non-empty) matches. Empty
// hash or mismatched algorithm is rejected so signin / signup /
// change cannot be probed by crafted input.
func ValidatePasswordHash(hash, algorithm string) bool {
	if hash == "" {
		return false
	}
	if algorithm != "" && algorithm != SupportedPasswordAlgorithm {
		return false
	}
	return strings.HasPrefix(hash, passwordHashPrefix)
}
