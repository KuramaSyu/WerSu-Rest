package config

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// silenceLog redirects the standard logger to io.Discard for the duration
// of the test so `Load` and `PrintConfig` do not pollute test output.
func silenceLog(t *testing.T) {
	t.Helper()
	orig := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(orig) })
}

// setRequiredEnv fills every env var that `Load` enforces via log.Fatal
// so the test can drive `Load` without the process exiting.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DISCORD_CLIENT_ID", "test-client-id")
	t.Setenv("DISCORD_CLIENT_SECRET", "test-client-secret")
	t.Setenv("SESSION_SECRET", "test-session-secret")
	t.Setenv("GRPC_SERVER_ADDRESS", "localhost:50051")
	t.Setenv("GRPC_SPICEDB_CREDENTIALS", "test-spicedb-creds")
	t.Setenv("GRPC_SPICEDB_ADDRESS", "localhost:50051")
	t.Setenv("IMGPROXY_ADDRESS", "http://localhost:8083")
	t.Setenv("S3_ENDPOINT", "http://localhost:9000")
	t.Setenv("S3_REGION", "us-east-1")
	t.Setenv("GARAGE_DEFAULT_ACCESS_KEY", "test-access-key")
	t.Setenv("GARAGE_DEFAULT_SECRET_KEY", "test-secret-key")
	t.Setenv("GARAGE_DEFAULT_BUCKET", "test-bucket")
	t.Setenv("JWT_SECRET", "test-jwt-secret")
}

// TestLoadReadsFrontendURLFromEnv pins the `docker run --env-file .env`
// delivery path: FRONTEND_URL set on the process environment must reach
// `AppConfig.FrontendURL` verbatim, with no defaulting and no .env-file
// interference.
func TestLoadReadsFrontendURLFromEnv(t *testing.T) {
	silenceLog(t)
	setRequiredEnv(t)
	t.Setenv("FRONTEND_URL", "https://my-frontend.example.com")

	cfg := Load()

	if cfg.FrontendURL != "https://my-frontend.example.com" {
		t.Fatalf("FrontendURL = %q, want %q", cfg.FrontendURL, "https://my-frontend.example.com")
	}
	if AppConfig.FrontendURL != "https://my-frontend.example.com" {
		t.Fatalf("AppConfig.FrontendURL = %q, want %q", AppConfig.FrontendURL, "https://my-frontend.example.com")
	}
}

// TestLoadReadsFrontendURLFromDotEnvFile pins the
// `docker run -v $(pwd)/.env:/app/.env` delivery path: FRONTEND_URL
// declared in a `.env` file in the working directory must reach
// `AppConfig.FrontendURL` when the variable is not already present in
// the process environment.
func TestLoadReadsFrontendURLFromDotEnvFile(t *testing.T) {
	silenceLog(t)

	dir := t.TempDir()
	contents := []byte(
		"DISCORD_CLIENT_ID=test-client-id\n" +
			"DISCORD_CLIENT_SECRET=test-client-secret\n" +
			"SESSION_SECRET=test-session-secret\n" +
			"GRPC_SERVER_ADDRESS=localhost:50051\n" +
			"GRPC_SPICEDB_CREDENTIALS=test-spicedb-creds\n" +
			"GRPC_SPICEDB_ADDRESS=localhost:50051\n" +
			"IMGPROXY_ADDRESS=http://localhost:8083\n" +
			"S3_ENDPOINT=http://localhost:9000\n" +
			"S3_REGION=us-east-1\n" +
			"GARAGE_DEFAULT_ACCESS_KEY=test-access-key\n" +
			"GARAGE_DEFAULT_SECRET_KEY=test-secret-key\n" +
			"GARAGE_DEFAULT_BUCKET=test-bucket\n" +
			"JWT_SECRET=test-jwt-secret\n" +
			"FRONTEND_URL=https://from-dotenv.example.com\n",
	)
	if err := os.WriteFile(filepath.Join(dir, ".env"), contents, 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	origCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origCwd) })

	// FRONTEND_URL must be unset so godotenv.Load will pick it up from
	// the file (godotenv.Load does not overwrite existing env values).
	origFrontend, hadFrontend := os.LookupEnv("FRONTEND_URL")
	if err := os.Unsetenv("FRONTEND_URL"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	t.Cleanup(func() {
		if hadFrontend {
			_ = os.Setenv("FRONTEND_URL", origFrontend)
		} else {
			_ = os.Unsetenv("FRONTEND_URL")
		}
	})

	cfg := Load()

	if cfg.FrontendURL != "https://from-dotenv.example.com" {
		t.Fatalf("FrontendURL = %q, want %q", cfg.FrontendURL, "https://from-dotenv.example.com")
	}
}

// TestLoadUsesDefaultFrontendURLWhenUnset pins the documented fallback:
// when FRONTEND_URL is absent from both env and .env, `Load` falls back
// to http://localhost:5173 instead of leaving the field empty.
func TestLoadUsesDefaultFrontendURLWhenUnset(t *testing.T) {
	silenceLog(t)
	setRequiredEnv(t)
	t.Setenv("FRONTEND_URL", "")

	cfg := Load()

	if cfg.FrontendURL != "http://localhost:5173" {
		t.Fatalf("FrontendURL = %q, want default %q", cfg.FrontendURL, "http://localhost:5173")
	}
}
