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

	if clientID == "" || clientSecret == "" {
		log.Fatal("DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET is not set")
	}

	if grpcServerAddress == "" {
		log.Fatal("GRPC_SERVER_ADDRESS environment variable is required")
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
	// Avoid printing sensitive values: clientSecret and sessionSecret.
	log.Println("Frontend URL:     ", cfg.FrontendURL)
	log.Println("gRPC Server Addr:", cfg.GRPCServerAddress)
}
