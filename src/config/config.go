package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

// Config holds application configuration
type Config struct {
	DiscordOAuthConfig *oauth2.Config
	SessionSecret      string
	FrontendURL        string
	GRPCServerAddress  string
	SpiceDbCredentials string
	SpiceDbAddress     string
	ImgproxyAddress    string
	S3Endpoint         string
	S3Region           string
	S3AccessKey        string
	S3SecretKey        string
	S3DefaultBucket    string
}

var AppConfig *Config

// Load initializes configuration from environment variables
func Load() *Config {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	clientID := os.Getenv("DISCORD_CLIENT_ID")
	clientSecret := os.Getenv("DISCORD_CLIENT_SECRET")
	redirectURL := os.Getenv("DISCORD_REDIRECT_URI")
	sessionSecret := os.Getenv("SESSION_SECRET")
	frontendURL := os.Getenv("FRONTEND_URL")
	grpcServerAddress := os.Getenv("GRPC_SERVER_ADDRESS")
	spiceDbCredentials := os.Getenv("GRPC_SPICEDB_CREDENTIALS")
	spiceDbAddress := os.Getenv("GRPC_SPICEDB_ADDRESS")
	ImgproxyAddress := os.Getenv("IMGPROXY_ADDRESS")
	S3Endpoint := os.Getenv("S3_ENDPOINT")
	S3Region := os.Getenv("S3_REGION")
	S3AccessKey := os.Getenv("GARAGE_DEFAULT_ACCESS_KEY")
	S3SecretKey := os.Getenv("GARAGE_DEFAULT_SECRET_KEY")
	S3DefaultBucket := os.Getenv("GARAGE_DEFAULT_BUCKET")

	// Validate required configuration

	if clientID == "" || clientSecret == "" {
		log.Fatal("DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET is not set")
	}

	if grpcServerAddress == "" {
		log.Fatal("GRPC_SERVER_ADDRESS environment variable is required")
	}

	if spiceDbCredentials == "" {
		log.Fatal("GRPC_SPICEDB_CREDENTIALS environment variable is required")
	}

	if spiceDbAddress == "" {
		log.Fatal("GRPC_SPICEDB_ADDRESS environment variable is required")
	}

	if sessionSecret == "" {
		log.Fatal("SESSION_SECRET environment variable is required")
	}

	if redirectURL == "" {
		redirectURL = "http://localhost:8080/api/auth/discord/callback"
	}

	if frontendURL == "" {
		frontendURL = "http://localhost:5173"
	}

	if ImgproxyAddress == "" {
		log.Fatal("IMGPROXY_ADDRESS environment variable is required")
	}

	if S3Endpoint == "" {
		log.Fatal("S3_ENDPOINT environment variable is required")
	}

	if S3Region == "" {
		log.Fatal("S3_REGION environment variable is required")
	}

	if S3AccessKey == "" {
		log.Fatal("S3_ACCESS_KEY environment variable is required")
	}

	if S3SecretKey == "" {
		log.Fatal("S3_SECRET_KEY environment variable is required")
	}

	if S3DefaultBucket == "" {
		log.Fatal("S3_DEFAULT_BUCKET environment variable is required")
	}

	discordOAuthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}

	AppConfig = &Config{
		DiscordOAuthConfig: discordOAuthConfig,
		SessionSecret:      sessionSecret,
		FrontendURL:        frontendURL,
		GRPCServerAddress:  grpcServerAddress,
		SpiceDbCredentials: spiceDbCredentials,
		SpiceDbAddress:     spiceDbAddress,
		ImgproxyAddress:    ImgproxyAddress,
		S3Endpoint:         S3Endpoint,
		S3Region:           S3Region,
		S3AccessKey:        S3AccessKey,
		S3SecretKey:        S3SecretKey,
		S3DefaultBucket:    S3DefaultBucket,
	}
	PrintConfig(AppConfig)
	return AppConfig
}

// PrintConfig logs some key configuration values.
func PrintConfig(cfg *Config) {
	log.Println("Discord OAuth Config:")
	log.Println("  ClientID:      ", cfg.DiscordOAuthConfig.ClientID) // Consider masking in production
	log.Println("  RedirectURL:   ", cfg.DiscordOAuthConfig.RedirectURL)
	log.Println("  Scopes:        ", cfg.DiscordOAuthConfig.Scopes)
	log.Println("Session Secret:  ", maskSensitiveValue(cfg.SessionSecret))
	log.Println("Frontend URL:     ", cfg.FrontendURL)
	log.Println("WerSu gRPC Server Addr:", cfg.GRPCServerAddress)
	log.Println("SpiceDB gRPC Server Addr:", cfg.SpiceDbAddress)
	log.Println("Imgproxy Address:", cfg.ImgproxyAddress)
	log.Println("S3 Endpoint:     ", cfg.S3Endpoint)
	log.Println("S3 Region:       ", cfg.S3Region)
	log.Println("S3 Access Key:   ", maskSensitiveValue(cfg.S3AccessKey))
	log.Println("S3 Secret Key:   ", maskSensitiveValue(cfg.S3SecretKey))
	log.Println("S3 Default Bucket:", cfg.S3DefaultBucket)
	// Avoid printing S3 Secret Key.
}

func maskSensitiveValue(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}
