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
	"github.com/KuramaSyu/WerSu-Rest/src/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
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

	// Allow CORS with Origin, allow providing of Authorization header to allow JWTs
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{appConfig.FrontendURL},
		AllowMethods:     []string{"GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept"},
		AllowCredentials: true,
	}))

	// Setup sessions
	store := cookie.NewStore([]byte(appConfig.SessionSecret))
	r.Use(sessions.Sessions("discord_auth", store))

	// Setup gRPC connection to WerSu backend service
	grpcConn, err := grpc.NewClient(
		appConfig.GRPCServerAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer grpcConn.Close()

	// Setup SpiceDb gRPC connection
	auth, err := GetAuthzedCLient(appConfig)
	if err != nil {
		log.Fatalf("Failed to connect to SpiceDb: %v", err)
	}

	// Setup S3 client
	s3Client, err := utils.NewS3Client(appConfig.S3Endpoint, appConfig.S3Region, appConfig.S3AccessKey, appConfig.S3SecretKey)
	if err != nil {
		log.Fatalf("Failed to create S3 client: %v", err)
	}

	// Initialize gRPC clients
	userGrpcClient := proto.NewUserServiceClient(grpcConn)
	noteGrpcClient := proto.NewNoteServiceClient(grpcConn)
	noteVersionGrpcClient := proto.NewNoteVersionServiceClient(grpcConn)
	directoryGrpcClient := proto.NewDirectoryServiceClient(grpcConn)
	permissionGrpcClient := proto.NewPermissionServiceClient(grpcConn)
	attachmentGrpcClient := proto.NewAttachmentServiceClient(grpcConn)
	shareingGrpcClient := proto.NewSharingServiceClient(grpcConn)

	// Initialize RSET controllers
	authController := controllers.NewAuthController(appConfig.DiscordOAuthConfig, &userGrpcClient, &shareingGrpcClient, appConfig.JwtSecret)
	noteController := controllers.NewNoteController(&noteGrpcClient)
	noteSearchController := controllers.NewSearchNoteController(&noteGrpcClient)
	noteVersionController := controllers.NewNoteVersionController(&noteVersionGrpcClient)
	directoryController := controllers.NewDirectoryController(&directoryGrpcClient)
	permissionController := controllers.NewPermissionController(&permissionGrpcClient)
	attachmentController := controllers.NewAttachmentController(&attachmentGrpcClient, auth, &appConfig.ImgproxyAddress, s3Client, appConfig.S3DefaultBucket)
	attachmentLinkController := controllers.NewAttachmentLinkController(&attachmentGrpcClient)
	sharingController := controllers.NewSharingController(&shareingGrpcClient)

	// Setup routes
	routes.SetupRouter(
		r,
		authController,
		noteController,
		noteSearchController,
		noteVersionController,
		directoryController,
		permissionController,
		attachmentController,
		attachmentLinkController,
		sharingController,
	)

	// Start the server
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

// Creates gRPC connection client to SpiceDB using credentials from config
func GetAuthzedCLient(conf *config.Config) (*authzed.Client, error) {
	client, err := authzed.NewClient(
		conf.SpiceDbAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpcutil.WithInsecureBearerToken(conf.SpiceDbCredentials),
	)

	if err != nil {
		log.Fatalf("unable to initialize client: %s", err)
	}
	return client, nil
}
