package utils

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetIdFromURL pulls a path parameter (default `id`) out of the gin
// context and validates it is non-empty and UUID-shaped. Returns the
// id, an http status code, and an error. Missing parameters are
// unreachable here because gin already 404'd the route.
func GetIdFromURL(c *gin.Context, param string) (string, int, error) {
	if param == "" {
		param = "id"
	}

	id := c.Param(param)
	if id == "" {
		return "", http.StatusBadRequest, fmt.Errorf("missing %s parameter in url", param)
	}

	// Accept any RFC 4122 variant (versions 1-7) so downstream
	// gRPC services that emit non-UUIDv7 ids still pass.
	if !isUUID(id) {
		return "", http.StatusBadRequest, fmt.Errorf("invalid %s parameter in url: not a UUID", param)
	}

	return id, http.StatusOK, nil
}

// isUUID checks UUID shape: 36 chars, hyphens at 8/13/18/23,
// version digit 1-7, variant nibble 8/9/a/b. It does not validate
// hex inside each group -- the upstream service is expected to.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	if !isVersionDigit(s[14]) {
		return false
	}
	if !isVariantNibble(s[19]) {
		return false
	}
	return true
}

func isVersionDigit(b byte) bool {
	return b >= '1' && b <= '7'
}

func isVariantNibble(b byte) bool {
	return b == '8' || b == '9' || b == 'a' || b == 'b' ||
		b == 'A' || b == 'B'
}
