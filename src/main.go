// @title GoToHell Gin REST API
// @oversion 1.0
// @description Provides all methods to persist data for GoToHell
// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name discord_auth

package main

import (
	"encoding/gob"
	"log"

	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/controllers"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/routes"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func init() {
	// Register types for session storage
	gob.Register(models.User{})
}

func main() {
	// Load configuration
	appConfig := config.Load()

	// Create router
	r := gin.Default()

	// Configure CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{appConfig.FrontendURL},
		AllowMethods:     []string{"GET", "POST", "DELETE", "PUT", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		AllowCredentials: true,
	}))

	// Setup sessions
	store := cookie.NewStore([]byte(appConfig.SessionSecret))
	r.Use(sessions.Sessions("discord_auth", store))

	// Setup gRPC connection
	grpcConn, err := grpc.NewClient(
		appConfig.GRPCServerAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer grpcConn.Close()

	// Initialize gRPC clients
	userGrpcClient := proto.NewUserServiceClient(grpcConn)
	noteGrpcClient := proto.NewNoteServiceClient(grpcConn)

	// Initialize RSET controllers
	authController := controllers.NewAuthController(appConfig.DiscordOAuthConfig, &userGrpcClient)
	noteController := controllers.NewNoteController(&noteGrpcClient)
	noteSearchController := controllers.NewSearchNoteController(&noteGrpcClient)

	// Setup routes
	routes.SetupRouter(
		r,
		authController,
		noteController,
		noteSearchController,
	)

	// Start the server
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
