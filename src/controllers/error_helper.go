package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetWersuGrpcError writes a generic 500 response for an unexpected gRPC
// error. It delegates to SetGinError, so transport-level gRPC failures
// (Unavailable / DeadlineExceeded / ResourceExhausted) are automatically
// upgraded to 503 just like everywhere else in the controller layer.
func SetWersuGrpcError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	SetGinError(c, http.StatusInternalServerError, err)
}
