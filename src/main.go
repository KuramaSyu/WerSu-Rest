package main

import (
	"log"

	"github.com/gin-gonic/gin"
	_ "github.com/yourname/gin-grpc-gateway/docs"
	"github.com/yourname/gin-grpc-gateway/internal/routes"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Gin gRPC Gateway API
// @version 1.0
// @description REST API gateway for gRPC services
// @host localhost:8080
// @BasePath /api/v1
func main() {
	r := gin.Default()

	routes.RegisterRoutes(r)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	log.Fatal(r.Run(":8080"))
}
