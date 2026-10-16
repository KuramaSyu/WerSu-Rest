package config

import (
	"log"
	"net/url"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

// Config holds application configuration
type Config struct {
	DiscordOAuthConfig *oauth2.Config
	// DiscordLinkOAuthConfig is the OAuth config used by the popup
	// link flow (`/api/auth/link/discord/*`). When nil the link
	// endpoint returns 503 -- this lets operators deploy login
	// first and roll out the link flow separately by configuring
	// the link redirect URL at the provider app.
	DiscordLinkOAuthConfig *oauth2.Config
	GoogleOAuthConfig      *oauth2.Config
	// GoogleLinkOAuthConfig mirrors DiscordLinkOAuthConfig for the
	// Google provider.
	GoogleLinkOAuthConfig *oauth2.Config
	WebAuthnRPID          string
	WebAuthnRPName     string
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
	JwtSecret          string
	// DatabaseDSN is consumed only by the /api/status probe. It is optional;
	// when empty, the database check is reported as not configured.
	DatabaseDSN string
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
	JwtSecret := os.Getenv("JWT_SECRET")
	// Optional: only used by the status probe. Not required for the app
	// to start.
	DatabaseDSN := os.Getenv("DATABASE_DSN")

	// Google OAuth (optional; only loaded when both env vars are set)
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	googleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URI")

	// Link OAuth redirect URLs. These point to
	// `/api/auth/link/<p>/callback` and must be registered at the
	// provider app alongside the regular login redirect URL. When
	// unset, the popup-based link flow returns 503 ("link OAuth is
	// not configured"); the SPA then falls back to the existing
	// `POST /api/auth/link/<p>` route.
	discordLinkRedirectURL := os.Getenv("DISCORD_LINK_REDIRECT_URI")
	googleLinkRedirectURL := os.Getenv("GOOGLE_LINK_REDIRECT_URI")

	// WebAuthn relying party. RPID is the registrable domain
	// (e.g. "iwillfind.it"); RP_NAME is the human-readable party
	// name shown in the authenticator prompt. The RP ID is derived
	// from FrontendURL -- scheme, port and path are stripped, so
	// "https://iwillfind.it/app" yields "iwillfind.it". When
	// FrontendURL is unset or unparseable, RPID stays empty and the
	// passkey endpoints return 503.
	webAuthnRPName := os.Getenv("WEBAUTHN_RP_NAME")
	webAuthnRPID := deriveWebAuthnRPID(frontendURL)

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

	if JwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
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

	// Google OAuth is optional. When the env vars are unset, the
	// GoogleStrategy won't be wired up and the /api/auth/google/* routes
	// return 503. The same shape applies to passkey support: without
	// WEBAUTHN_RP_ID, the passkey endpoints return 503.
	var googleOAuthConfig *oauth2.Config
	if googleClientID != "" && googleClientSecret != "" {
		googleOAuthConfig = &oauth2.Config{
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleRedirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		}
	}

	// Link OAuth configs reuse the regular OAuth config's ClientID /
	// Secret / Endpoint but use a separate RedirectURL that points
	// at `/api/auth/link/<p>/callback`. Without it, the popup link
	// flow is disabled (returns 503); the SPA can still use the
	// existing `POST /api/auth/link/<p>` fallback.
	var discordLinkOAuthConfig *oauth2.Config
	if clientID != "" && clientSecret != "" && discordLinkRedirectURL != "" {
		discordLinkOAuthConfig = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  discordLinkRedirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint:     discordOAuthConfig.Endpoint,
		}
	}
	var googleLinkOAuthConfig *oauth2.Config
	if googleOAuthConfig != nil && googleLinkRedirectURL != "" {
		googleLinkOAuthConfig = &oauth2.Config{
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleLinkRedirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     googleOAuthConfig.Endpoint,
		}
	}

	AppConfig = &Config{
		DiscordOAuthConfig:      discordOAuthConfig,
		DiscordLinkOAuthConfig:  discordLinkOAuthConfig,
		GoogleOAuthConfig:       googleOAuthConfig,
		GoogleLinkOAuthConfig:   googleLinkOAuthConfig,
		WebAuthnRPID:            webAuthnRPID,
		WebAuthnRPName:     webAuthnRPName,
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
		JwtSecret:          JwtSecret,
		DatabaseDSN:        DatabaseDSN,
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
	if cfg.DiscordLinkOAuthConfig != nil {
		log.Println("Discord Link OAuth RedirectURL:", cfg.DiscordLinkOAuthConfig.RedirectURL)
	} else {
		log.Println("Discord Link OAuth: (not configured)")
	}
	if cfg.GoogleOAuthConfig != nil {
		log.Println("Google OAuth Config:")
		log.Println("  ClientID:      ", cfg.GoogleOAuthConfig.ClientID)
		log.Println("  RedirectURL:   ", cfg.GoogleOAuthConfig.RedirectURL)
	} else {
		log.Println("Google OAuth:    (not configured)")
	}
	if cfg.GoogleLinkOAuthConfig != nil {
		log.Println("Google Link OAuth RedirectURL:", cfg.GoogleLinkOAuthConfig.RedirectURL)
	} else {
		log.Println("Google Link OAuth: (not configured)")
	}
	if cfg.WebAuthnRPID != "" {
		log.Println("WebAuthn RP ID:  ", cfg.WebAuthnRPID)
		log.Println("WebAuthn RP Name:", cfg.WebAuthnRPName)
	} else {
		log.Println("WebAuthn:        (not configured)")
	}
	log.Println("Session Secret:  ", maskSensitiveValue(cfg.SessionSecret))
	log.Println("JWT Secret:      ", maskSensitiveValue(cfg.JwtSecret)) // Assuming JWT secret is same as session secret
	log.Println("Frontend URL:    ", cfg.FrontendURL)
	log.Println("WerSu gRPC Server Addr:", cfg.GRPCServerAddress)
	log.Println("SpiceDB gRPC Server Addr:", cfg.SpiceDbAddress)
	log.Println("Imgproxy Address:", cfg.ImgproxyAddress)
	log.Println("S3 Endpoint:     ", cfg.S3Endpoint)
	log.Println("S3 Region:       ", cfg.S3Region)
	log.Println("S3 Access Key:   ", maskSensitiveValue(cfg.S3AccessKey))
	log.Println("S3 Secret Key:   ", maskSensitiveValue(cfg.S3SecretKey))
	if cfg.DatabaseDSN != "" {
		log.Println("Database DSN:     ", maskSensitiveValue(cfg.DatabaseDSN))
	} else {
		log.Println("Database DSN:     (not configured)")
	}
	log.Println("S3 Default Bucket:", cfg.S3DefaultBucket)
	// Avoid printing S3 Secret Key.
}

func maskSensitiveValue(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

// deriveWebAuthnRPID strips the scheme, port and path off
// frontendURL and returns the bare host (e.g. "iwillfind.it"). It
// returns an empty string when frontendURL is empty or unparseable,
// so callers can treat that as "passkey support not configured".
func deriveWebAuthnRPID(frontendURL string) string {
	if frontendURL == "" {
		return ""
	}
	u, err := url.Parse(frontendURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}
