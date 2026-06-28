package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetWersuGrpcError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"WerSu gRPC failed with:": err.Error()})
}
