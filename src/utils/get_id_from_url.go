package utils

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetIdFromURL pulls a path parameter (default `id`) out of the gin
// context and validates it is non-empty.
//
// Returns the id, an http status code, and an error.  An empty
// parameter yields StatusBadRequest; missing parameters are
// unreachable here because gin already 404'd the route.
func GetIdFromURL(c *gin.Context, param string) (string, int, error) {
	if param == "" {
		param = "id"
	}

	// check that param is present
	id := c.Param(param)
	if id == "" {
		return "", http.StatusBadRequest, fmt.Errorf("missing %s parameter in url", param)
	}

	// check that param is uuidv7 shape
	if !isUUIDv7(id) {
		return "", http.StatusBadRequest, fmt.Errorf("invalid %s parameter in url: not UUIDv7", param)
	}

	return id, http.StatusOK, nil
}

// isUUIDv7 checks if a string is a valid UUIDv7 (valid shape, not valid id)
func isUUIDv7(s string) bool {
	// check length
	if len(s) != 36 {
		return false
	}

	// check version character (14th character)
	if s[14] != '7' {
		return false
	}

	// check hyphen positions
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}

	return true
}
