package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
)

func init() {
	// register types for session storage. mirrors main.go.
	gob.Register(models.User{})
}

// newAuthTestRouter wires the AuthController into a Gin router with
// the in-memory cookie store. The fake gRPC client is plugged into
// the controller so no real gRPC server is needed.
func newAuthTestRouter(t *testing.T, fake auth.AuthServiceClientIface) *gin.Engine {
	t.Helper()
	return newAuthTestRouterWithLinkOAuth(t, fake, nil, nil, nil)
}

// newAuthTestRouterWithLinkOAuth wires the same router but with the
// popup link OAuth configs plumbed through. Tests that exercise the
// popup link flow pass non-nil configs; everything else uses the
// default nil-passthrough helper above. The optional `mutate` hook
// runs after construction so tests can override the userinfo URLs
// (which default to the real Discord / Google endpoints) to point
// at a mock httptest server.
func newAuthTestRouterWithLinkOAuth(
	t *testing.T,
	fake auth.AuthServiceClientIface,
	discordLink, googleLink *oauth2.Config,
	mutate func(*AuthController),
) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	r.Use(sessions.Sessions("discord_auth", store))

	// Save and restore FrontendURL so tests don't leak config
	// across each other. The link-complete HTML page embeds the
	// origin in its postMessage targetOrigin.
	prev := config.AppConfig
	config.AppConfig = &config.Config{FrontendURL: "http://localhost:5173"}
	t.Cleanup(func() { config.AppConfig = prev })

	ac := NewAuthController(
		nil, // discord OAuth config (login flow) -- unused in unit tests
		nil, // google OAuth config (login flow) -- unused in unit tests
		fake,
		nil, // shareService not used
		"test-jwt-secret",
		"", "", nil, // WebAuthn not configured -- passkey endpoints return 503
		discordLink,
		googleLink,
	)
	if mutate != nil {
		mutate(ac)
	}
	t.Cleanup(func() { _ = ac })

	authGroup := r.Group("/auth")
	authGroup.POST("/login", ac.PostLogin)
	authGroup.POST("/signup", ac.PostSignup)
	authGroup.GET("/user", ac.GetUser)
	authGroup.GET("/me/credentials", ac.GetLinkedCredentials)
	authGroup.POST("/link/discord", ac.PostLinkDiscord)
	authGroup.POST("/link/google", ac.PostLinkGoogle)
	authGroup.POST("/link/password", ac.PostLinkPassword)
	authGroup.POST("/password/change", ac.PostChangePassword)
	authGroup.POST("/passkey/register/begin", ac.PostPasskeyRegisterBegin)
	authGroup.POST("/passkey/register/finish", ac.PostPasskeyRegisterFinish)
	authGroup.POST("/passkey/login/begin", ac.PostPasskeyLoginBegin)
	authGroup.POST("/passkey/login/finish", ac.PostPasskeyLoginFinish)
	authGroup.GET("/passkey/list", ac.GetPasskeysForMe)
	authGroup.DELETE("/passkey/:id", ac.DeletePasskey)
	authGroup.POST("/link/passkey/begin", ac.PostLinkPasskeyBegin)
	authGroup.POST("/link/passkey/finish", ac.PostLinkPasskeyFinish)
	authGroup.GET("/link/:p/init", ac.GetLinkInit)
	authGroup.GET("/link/:p/callback", ac.GetLinkCallback)
	authGroup.GET("/link/:p/complete", ac.GetLinkComplete)
	authGroup.GET("/logout", ac.Logout)

	usersGroup := r.Group("/api/users")
	usersGroup.POST("", ac.PostUser)
	usersGroup.PATCH("/:id", ac.PatchUser)
	return r
}

// doRequest is a tiny helper that POSTs (or GETs) a request and returns
// the response recorder.
func doRequest(r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		switch v := body.(type) {
		case []byte:
			req = httptest.NewRequest(method, path, bytes.NewReader(v))
		case string:
			req = httptest.NewRequest(method, path, strings.NewReader(v))
		default:
			b, err := json.Marshal(v)
			if err != nil {
				panic("test body marshal: " + err.Error())
			}
			req = httptest.NewRequest(method, path, bytes.NewReader(b))
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ---------- PostLogin ----------

func TestPostLoginUnknownKind(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{Kind: "magic-link"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Unknown login kind") {
		t.Errorf("body = %q, want 'Unknown login kind'", w.Body.String())
	}
}

func TestPostLoginPasswordSigninBadJSON(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/login", []byte(`{not json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLoginPasswordMissingFields(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{Kind: auth.KindPassword, Email: ""})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLoginPasswordInvalidCredentials(t *testing.T) {
	// The strategy's signin path returns InvalidCredentialsError
	// specifically when the user isn't found. Any other gRPC
	// error propagates and utils.SetGinError decides the HTTP status.
	// For a NotFound the controller returns 401; for any other
	// gRPC code, it falls through to 500 (or an upgrade if the
	// code matches Unavailable/DeadlineExceeded/etc).
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{
		Kind:     auth.KindPassword,
		Email:    "alice@example.com",
		Password: "anypw",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid email or password") {
		t.Errorf("body = %q, want generic error", w.Body.String())
	}
}

func TestPostLoginPasswordSuccess(t *testing.T) {
	hash, _ := (auth.Argon2Hasher{}).Hash("realpw")
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			if in.GetEmail() != "alice@example.com" {
				t.Errorf("email = %q, want alice@example.com", in.GetEmail())
			}
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{
					Kind:    proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
					Payload: &proto.Credential_PasswordHash{PasswordHash: hash},
				},
				User: &proto.UserAuth{Id: "u-1", Email: "alice@example.com"},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{
		Kind:     auth.KindPassword,
		Email:    "alice@example.com",
		Password: "realpw",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["id"] != "u-1" {
		t.Errorf("id = %v, want u-1", got["id"])
	}
	if got["email"] != "alice@example.com" {
		t.Errorf("email = %v", got["email"])
	}
}

func TestPostLoginPasswordRejectsEmptyPassword(t *testing.T) {
	// Empty password is rejected at the controller before reaching
	// the strategy.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{
		Kind:     auth.KindPassword,
		Email:    "alice@example.com",
		Password: "",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLoginPasskeyKindRejected(t *testing.T) {
	// Passkey login now goes through /auth/passkey/login/{begin,finish},
	// not /auth/login. A kind=passkey request to /auth/login should
	// be rejected with 400 because the unified endpoint no longer
	// knows how to dispatch it.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{Kind: auth.KindPasskeyKind})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "its own route") {
		t.Errorf("body = %q, want 'requires its own route'", w.Body.String())
	}
}

// ---------- PostSignup ----------

func TestPostSignupBadJSON(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/signup", []byte(`{not json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostSignupMissingFields(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/signup", SignupRequest{Email: "", Password: ""})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostSignupConflict(t *testing.T) {
	// When the gRPC service returns AlreadyExists, the controller
	// maps to 409 with a generic "email already in use" message.
	fake := &auth.FakeAuthClient{
		OnCreateUserAuth: func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "email taken")
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/auth/signup", SignupRequest{
		Email:    "taken@example.com",
		Username: "alice",
		Password: "pw",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if !strings.Contains(w.Body.String(), "email already in use") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestPostSignupSuccess(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			if in.PasswordHash == "" {
				t.Error("server hash was empty")
			}
			if in.PasswordHash == "x" {
				t.Error("plaintext password leaked to gRPC")
			}
			// Verify the stored hash reproduces the original
			// plaintext via the standard argon2id verify path.
			ok, err := (auth.Argon2Hasher{}).Verify("x", in.PasswordHash)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Error("server hash did not reproduce plaintext")
			}
			return &proto.CreateUserAuthResponse{
				User: &proto.UserAuth{Id: "new-u", Email: in.Email},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/auth/signup", SignupRequest{
		Email:    "alice@example.com",
		Username: "alice",
		Password: "x",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["id"] != "new-u" {
		t.Errorf("id = %v, want new-u", got["id"])
	}
}

// ---------- GetUser ----------

func TestGetUserNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/user", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestGetUserLoggedIn(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnGetUserAuth: func(in *proto.GetUserAuthRequest) (*proto.GetUserAuthResponse, error) {
			if in.GetUserId() != "u-1" {
				t.Errorf("user id = %q, want u-1", in.GetUserId())
			}
			return &proto.GetUserAuthResponse{
				User: &proto.UserAuth{Id: "u-1", Email: "alice@example.com"},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	// Build a request that has a session cookie carrying the user id.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/user", nil)
	// Inject the session via the gin session middleware.
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
		c.Status(http.StatusOK)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("session setup failed: %d", rec.Code)
	}

	// Now re-issue the /auth/user request that carries the saved cookie.
	req = httptest.NewRequest(http.MethodGet, "/auth/user", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GetUser status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &got)
	if got["id"] != "u-1" {
		t.Errorf("id = %v, want u-1", got["id"])
	}
}

// ---------- GetLinkedCredentials ----------

func TestGetLinkedCredentialsNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/me/credentials", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestGetLinkedCredentialsSuccess(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnListLinkedCredentials: func(in *proto.ListLinkedCredentialsRequest) (*proto.ListLinkedCredentialsResponse, error) {
			if in.GetUserId() != "u-1" {
				t.Errorf("user id = %q, want u-1", in.GetUserId())
			}
			return &proto.ListLinkedCredentialsResponse{
				Credentials: []*proto.Credential{
					{Kind: proto.CredentialKind_CREDENTIAL_KIND_DISCORD, Payload: &proto.Credential_DiscordId{DiscordId: "12345"}},
					{Kind: proto.CredentialKind_CREDENTIAL_KIND_PASSWORD, Payload: &proto.Credential_PasswordHash{PasswordHash: "$argon2id$..."}},
				},
				Passkeys: []*proto.Passkey{
					{Id: "pk-1", FriendlyName: "MacBook"},
				},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	// Set up a session with the user id.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me/credentials", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req = httptest.NewRequest(http.MethodGet, "/auth/me/credentials", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &got)
	if creds, ok := got["credentials"].([]any); !ok || len(creds) != 2 {
		t.Errorf("credentials = %v", got["credentials"])
	}
	if pks, ok := got["passkeys"].([]any); !ok || len(pks) != 1 {
		t.Errorf("passkeys = %v", got["passkeys"])
	}
}

// ---------- GetPasskeysForMe ----------

func TestGetPasskeysForMeNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/passkey/list", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestGetPasskeysForMeSuccess(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnListPasskeys: func(in *proto.ListPasskeysRequest) (*proto.ListPasskeysResponse, error) {
			if in.GetUserId() != "u-1" {
				t.Errorf("user id = %q, want u-1", in.GetUserId())
			}
			if in.GetIncludeRevoked() {
				t.Errorf("include_revoked = true, want default false")
			}
			return &proto.ListPasskeysResponse{
				Passkeys: []*proto.Passkey{
					{Id: "pk-1", FriendlyName: "MacBook"},
					{Id: "pk-2", FriendlyName: "YubiKey"},
				},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/passkey/list", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req = httptest.NewRequest(http.MethodGet, "/auth/passkey/list", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &got)
	pks, ok := got["passkeys"].([]any)
	if !ok || len(pks) != 2 {
		t.Fatalf("passkeys = %v, want 2 entries", got["passkeys"])
	}
}

func TestGetPasskeysForMeIncludeRevoked(t *testing.T) {
	var sawIncludeRevoked bool
	fake := &auth.FakeAuthClient{
		OnListPasskeys: func(in *proto.ListPasskeysRequest) (*proto.ListPasskeysResponse, error) {
			sawIncludeRevoked = in.GetIncludeRevoked()
			return &proto.ListPasskeysResponse{}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/passkey/list", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req = httptest.NewRequest(http.MethodGet, "/auth/passkey/list?include_revoked=true", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d", rec2.Code)
	}
	if !sawIncludeRevoked {
		t.Errorf("expected include_revoked to be forwarded as true")
	}
}

// ---------- DeletePasskey ----------

func TestDeletePasskeyNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodDelete, "/auth/passkey/pk-1", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestDeletePasskeySuccess(t *testing.T) {
	var revoked *proto.RevokePasskeyRequest
	fake := &auth.FakeAuthClient{
		OnRevokePasskey: func(in *proto.RevokePasskeyRequest) (*emptypb.Empty, error) {
			revoked = in
			return &emptypb.Empty{}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/passkey/pk-1", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req = httptest.NewRequest(http.MethodDelete, "/auth/passkey/pk-1", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec2.Code)
	}
	if revoked == nil {
		t.Fatal("RevokePasskey was not called")
	}
	if revoked.PasskeyId != "pk-1" || revoked.UserId != "u-1" || revoked.RequesterId != "u-1" {
		t.Errorf("revoke = %+v", revoked)
	}
}

func TestDeletePasskeyPasskeyMissingReturns404(t *testing.T) {
	// gRPC returns NotFound when the row does not exist (or belongs to a
	// different user, after the server's permission filter). The controller
	// surfaces that as 404 so the frontend never sees a difference.
	fake := &auth.FakeAuthClient{
		OnRevokePasskey: func(*proto.RevokePasskeyRequest) (*emptypb.Empty, error) {
			return nil, status.Error(codes.NotFound, "passkey not found")
		},
	}
	r := newAuthTestRouter(t, fake)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodDelete, "/auth/passkey/pk-missing", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for missing passkey", w.Code)
	}
}

func TestDeletePasskeyCrossUserHidesAs404(t *testing.T) {
	// gRPC may translate a "not the owner's passkey" check into
	// PermissionDenied (the actor has no rights on this row) or NotFound.
	// Both must surface as 404 to keep the endpoint an existence-unaware
	// black box.
	fake := &auth.FakeAuthClient{
		OnRevokePasskey: func(*proto.RevokePasskeyRequest) (*emptypb.Empty, error) {
			return nil, status.Error(codes.PermissionDenied, "passkey not owned by caller")
		},
	}
	r := newAuthTestRouter(t, fake)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodDelete, "/auth/passkey/pk-other-user", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (PermissionDenied must collapse to 404)", w.Code)
	}
}

func TestDeletePasskeyAlreadyRevokedIs204(t *testing.T) {
	// Idempotent revoke: if gRPC says the row is already revoked we
	// surface 204 instead of 500 so a flaky network that double-fires
	// the request still resolves cleanly.
	fake := &auth.FakeAuthClient{
		OnRevokePasskey: func(*proto.RevokePasskeyRequest) (*emptypb.Empty, error) {
			return nil, status.Error(codes.AlreadyExists, "already revoked")
		},
	}
	r := newAuthTestRouter(t, fake)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodDelete, "/auth/passkey/pk-1", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for already-revoked passkey", w.Code)
	}
}

// ---------- PostLinkPassword ----------

func TestPostLinkPasswordNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/link/password", LinkPasswordRequest{Password: "anything"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestPostLinkPasswordBadJSON(t *testing.T) {
	// The controller checks auth before validating the body, so we
	// need a session before the test can exercise the bad-JSON path.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/password", bytes.NewReader([]byte(`{not json`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLinkPasswordMissingPassword(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	body, _ := json.Marshal(LinkPasswordRequest{Password: ""})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLinkPasswordSuccess(t *testing.T) {
	var linked *proto.LinkCredentialRequest
	fake := &auth.FakeAuthClient{
		OnLinkCredential: func(in *proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			linked = in
			return &proto.LinkCredentialResponse{
				Credential: &proto.Credential{Id: "c-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_PASSWORD},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/link/password", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})

	body, _ := json.Marshal(LinkPasswordRequest{Password: "anything"})
	req = httptest.NewRequest(http.MethodPost, "/auth/link/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	if linked == nil {
		t.Fatal("LinkCredential was not called")
	}
	if linked.UserId != "u-1" || linked.RequesterId != "u-1" {
		t.Errorf("user/requester = (%q, %q), want (u-1, u-1)", linked.UserId, linked.RequesterId)
	}
	if linked.Kind != proto.CredentialKind_CREDENTIAL_KIND_PASSWORD {
		t.Errorf("kind = %v, want PASSWORD", linked.Kind)
	}
	if linked.GetPasswordHash() == "" {
		t.Errorf("password hash was empty")
	}
	if linked.GetPasswordHash() == "anything" {
		t.Errorf("plaintext password was sent to gRPC")
	}
	ok, err := (auth.Argon2Hasher{}).Verify("anything", linked.GetPasswordHash())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Errorf("server hash did not reproduce plaintext")
	}
}

// ---------- PostChangePassword ----------

// changePasswordFixture seeds the fake with a stored hash for the
// current password and returns a router with an authenticated session.
func changePasswordFixture(t *testing.T, fake auth.AuthServiceClientIface) (*gin.Engine, string) {
	t.Helper()
	r := newAuthTestRouter(t, fake)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1", Email: "alice@example.com"})
		_ = s.Save()
	})
	return r, rec.Result().Header.Get("Set-Cookie")
}

func TestPostChangePasswordNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/password/change", ChangePasswordRequest{
		CurrentPassword: "old", NewPassword: "new",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestPostChangePasswordMissingFields(t *testing.T) {
	hash, _ := auth.Argon2Hasher{}.Hash("oldpw")
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "c-1", Payload: &proto.Credential_PasswordHash{PasswordHash: hash}},
			}, nil
		},
	}
	r, cookie := changePasswordFixture(t, fake)

	body, _ := json.Marshal(ChangePasswordRequest{CurrentPassword: "", NewPassword: "new"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
}

func TestPostChangePasswordSameAsCurrent(t *testing.T) {
	hash, _ := auth.Argon2Hasher{}.Hash("oldpw")
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "c-1", Payload: &proto.Credential_PasswordHash{PasswordHash: hash}},
			}, nil
		},
	}
	r, cookie := changePasswordFixture(t, fake)

	body, _ := json.Marshal(ChangePasswordRequest{CurrentPassword: "same", NewPassword: "same"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostChangePasswordWrongCurrent(t *testing.T) {
	storedHash, _ := auth.Argon2Hasher{}.Hash("oldpw")
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "c-1", Payload: &proto.Credential_PasswordHash{PasswordHash: storedHash}},
			}, nil
		},
		// Unlink/Link should never be called on a wrong-password path.
		OnUnlinkCredential: func(*proto.UnlinkCredentialRequest) (*emptypb.Empty, error) {
			t.Fatal("UnlinkCredential was called on wrong-current-password path")
			return nil, nil
		},
		OnLinkCredential: func(*proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			t.Fatal("LinkCredential was called on wrong-current-password path")
			return nil, nil
		},
	}
	r, cookie := changePasswordFixture(t, fake)

	body, _ := json.Marshal(ChangePasswordRequest{
		CurrentPassword: "WRONG",
		NewPassword:     "newpw",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
}

func TestPostChangePasswordNoPasswordSet(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(*proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			return nil, status.Error(codes.NotFound, "no credential")
		},
	}
	r, cookie := changePasswordFixture(t, fake)

	body, _ := json.Marshal(ChangePasswordRequest{
		CurrentPassword: "oldpw",
		NewPassword:     "newpw",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
}

func TestPostChangePasswordSuccess(t *testing.T) {
	storedHash, _ := auth.Argon2Hasher{}.Hash("oldpw")
	var (
		gotUnlink *proto.UnlinkCredentialRequest
		gotLink   *proto.LinkCredentialRequest
	)
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			if in.GetEmail() != "alice@example.com" {
				t.Errorf("lookup email = %q, want alice@example.com", in.GetEmail())
			}
			return &proto.FindCredentialByProviderResponse{
				Credential: &proto.Credential{Id: "c-old", Payload: &proto.Credential_PasswordHash{PasswordHash: storedHash}},
			}, nil
		},
		OnUnlinkCredential: func(in *proto.UnlinkCredentialRequest) (*emptypb.Empty, error) {
			gotUnlink = in
			return &emptypb.Empty{}, nil
		},
		OnLinkCredential: func(in *proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			gotLink = in
			return &proto.LinkCredentialResponse{
				Credential: &proto.Credential{Id: "c-new"},
			}, nil
		},
	}
	r, cookie := changePasswordFixture(t, fake)

	body, _ := json.Marshal(ChangePasswordRequest{
		CurrentPassword: "oldpw",
		NewPassword:     "newpw",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if gotUnlink == nil {
		t.Fatal("UnlinkCredential was not called")
	}
	if gotUnlink.GetCredentialId() != "c-old" {
		t.Errorf("unlink credential id = %q, want c-old", gotUnlink.GetCredentialId())
	}
	if gotUnlink.GetUserId() != "u-1" || gotUnlink.GetRequesterId() != "u-1" {
		t.Errorf("unlink user/requester = (%q, %q)", gotUnlink.GetUserId(), gotUnlink.GetRequesterId())
	}
	if gotLink == nil {
		t.Fatal("LinkCredential was not called")
	}
	if gotLink.GetUserId() != "u-1" || gotLink.GetRequesterId() != "u-1" {
		t.Errorf("link user/requester = (%q, %q)", gotLink.GetUserId(), gotLink.GetRequesterId())
	}
	if gotLink.Kind != proto.CredentialKind_CREDENTIAL_KIND_PASSWORD {
		t.Errorf("link kind = %v, want PASSWORD", gotLink.Kind)
	}
	if gotLink.GetPasswordHash() == "" {
		t.Fatal("link hash was empty")
	}
	if gotLink.GetPasswordHash() == "newpw" {
		t.Fatal("plaintext password leaked to gRPC")
	}
	ok, err := (auth.Argon2Hasher{}).Verify("newpw", gotLink.GetPasswordHash())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Errorf("server hash did not reproduce new plaintext")
	}
}

// ---------- PostLinkDiscord ----------

func TestPostLinkDiscordMissingDiscordId(t *testing.T) {
	// The controller checks auth before validating the query, so
	// "missing discord_id" only surfaces when the user is logged
	// in. Without a session, the request returns 401.
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, newAuthTestRouter(t, &auth.FakeAuthClient{}), func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/discord?username=alice", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLinkDiscordSuccess(t *testing.T) {
	var linked *proto.LinkCredentialRequest
	fake := &auth.FakeAuthClient{
		OnLinkCredential: func(in *proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			linked = in
			return &proto.LinkCredentialResponse{
				Credential: &proto.Credential{Id: "c-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_DISCORD},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/link/discord?discord_id=12345", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})

	req = httptest.NewRequest(http.MethodPost, "/auth/link/discord?discord_id=12345", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	if linked == nil {
		t.Fatal("LinkCredential was not called")
	}
	if linked.GetDiscordId() != "12345" {
		t.Errorf("discord_id = %q, want 12345", linked.GetDiscordId())
	}
	if linked.Kind != proto.CredentialKind_CREDENTIAL_KIND_DISCORD {
		t.Errorf("kind = %v, want DISCORD", linked.Kind)
	}
}

// ---------- PostLinkGoogle ----------

func TestPostLinkGoogleMissingGoogleId(t *testing.T) {
	// Same as PostLinkDiscord: the controller checks auth first.
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, newAuthTestRouter(t, &auth.FakeAuthClient{}), func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/google", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostLinkGoogleSuccess(t *testing.T) {
	var linked *proto.LinkCredentialRequest
	fake := &auth.FakeAuthClient{
		OnLinkCredential: func(in *proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			linked = in
			return &proto.LinkCredentialResponse{
				Credential: &proto.Credential{Id: "c-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_GOOGLE},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/link/google?google_id=sub-1", nil)
	rec = runWithSession(req, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})

	req = httptest.NewRequest(http.MethodPost, "/auth/link/google?google_id=sub-1", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	if linked == nil {
		t.Fatal("LinkCredential was not called")
	}
	if linked.GetGoogleId() != "sub-1" {
		t.Errorf("google_id = %q, want sub-1", linked.GetGoogleId())
	}
}

// ---------- Popup-based OAuth link flow ----------
//
// The link endpoints (`/link/<p>/init`, `/link/<p>/callback`,
// `/link/<p>/complete`) drive the popup-based OAuth link flow.
// They share the session cookie with the main window, generate
// and verify a per-provider CSRF state, and serve a tiny HTML page
// at `/complete` that posts the link result to `window.opener`.
//
// Tests cover the controller surface (state plumbing, error
// mapping, redirects) and the link dispatch
// (`linkFromOAuth`), but mock the OAuth provider with an
// httptest server so no real Discord/Google call happens.

// linkFakeServer stands up a minimal OAuth provider for the link
// callback tests. POST `/token` returns a fake access token;
// GET `/userinfo` runs the supplied handler. The returned
// *oauth2.Config points at this server so Exchange / Client call
// back into it.
func linkFakeServer(t *testing.T, userinfo http.HandlerFunc) (*httptest.Server, *oauth2.Config) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"fake-token","token_type":"Bearer","expires_in":3600}`))
		default:
			userinfo(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	cfg := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  ts.URL + "/callback",
		Scopes:       []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  ts.URL + "/authorize",
			TokenURL: ts.URL + "/token",
		},
	}
	return ts, cfg
}

// seedLinkSession sets the user and the link state in the session,
// then returns the Set-Cookie header to attach to the next request.
// `state` is what the test expects the callback to echo back; if
// empty, no state is seeded (the test will exercise the state-mismatch
// branch).
func seedLinkSession(t *testing.T, r *gin.Engine, userID, p, state string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: userID})
		if state != "" {
			s.Set(linkStateKey(p), state)
			s.Set(linkStateKey(p)+"_user", userID)
		}
		_ = s.Save()
	})
	return rec.Result().Header.Get("Set-Cookie")
}

// ---------- GetLinkInit ----------

func TestGetLinkInitUnauthenticated(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/link/discord/init", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestGetLinkInitUnknownProvider(t *testing.T) {
	// A provider we don't recognize returns 503 even with a
	// session: linkOAuthFor returns ok=false for "foo".
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	cookie := seedLinkSession(t, r, "u-1", "discord", "")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/foo/init", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestGetLinkInitOAuthNotConfigured(t *testing.T) {
	// Session is set, but Discord link OAuth is nil -> 503.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	cookie := seedLinkSession(t, r, "u-1", "discord", "")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/init", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "discord") {
		t.Errorf("body = %q, want provider name in error", w.Body.String())
	}
}

func TestGetLinkInitDiscordRedirectsWithState(t *testing.T) {
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	cookie := seedLinkSession(t, r, "u-1", "discord", "")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/init", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cfg.Endpoint.AuthURL+"?") {
		t.Fatalf("Location = %q, want prefix %q", loc, cfg.Endpoint.AuthURL+"?")
	}
	// Extract the state query parameter; the callback must use the
	// same value for the CSRF check to pass.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("state was not appended to authorize URL")
	}

	// The state must be stored in the session under the
	// provider-scoped key. The init response sets a Set-Cookie
	// header that re-establishes the session.
	setCookies := w.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range setCookies {
		if c.Name == "discord_auth" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("session cookie was not set on /init")
	}
	// Fetch the session via the new cookie and confirm the state
	// was stored under the namespaced key.
	rec := httptest.NewRecorder()
	probeReq := httptest.NewRequest(http.MethodGet, "/auth/user", nil)
	probeReq.Header.Set("Cookie", sessCookie.String())
	probe := httptest.NewRecorder()
	r.ServeHTTP(probe, probeReq)
	_ = rec
	// Re-issue a probe that runs the session middleware and reads
	// the state we stored. Use a one-shot route for this.
	var sawState string
	var sawBoundUser string
	r.GET("/__probe", func(c *gin.Context) {
		s := sessions.Default(c)
		sawState, _ = s.Get(linkStateKey("discord")).(string)
		sawBoundUser, _ = s.Get(linkStateKey("discord") + "_user").(string)
		c.Status(http.StatusOK)
	})
	probeReq = httptest.NewRequest(http.MethodGet, "/__probe", nil)
	probeReq.Header.Set("Cookie", sessCookie.String())
	r.ServeHTTP(httptest.NewRecorder(), probeReq)
	if sawState != state {
		t.Errorf("session state = %q, want %q", sawState, state)
	}
	if sawBoundUser != "u-1" {
		t.Errorf("bound user = %q, want u-1", sawBoundUser)
	}
}

func TestGetLinkInitGoogleRedirectsWithState(t *testing.T) {
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, nil, cfg, nil)
	cookie := seedLinkSession(t, r, "u-1", "google", "")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/google/init", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cfg.Endpoint.AuthURL+"?") {
		t.Fatalf("Location = %q, want prefix %q", loc, cfg.Endpoint.AuthURL+"?")
	}
}

// ---------- GetLinkCallback ----------

func TestGetLinkCallbackUnauthenticated(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/link/discord/callback?code=x&state=y", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestGetLinkCallbackUnknownProvider(t *testing.T) {
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	cookie := seedLinkSession(t, r, "u-1", "discord", "good-state")
	req := httptest.NewRequest(http.MethodGet, "/auth/link/foo/callback?code=x&state=good-state", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestGetLinkCallbackOAuthNotConfigured(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	cookie := seedLinkSession(t, r, "u-1", "discord", "good-state")
	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?code=x&state=good-state", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestGetLinkCallbackStateMismatch(t *testing.T) {
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	cookie := seedLinkSession(t, r, "u-1", "discord", "seeded-state")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?code=x&state=other-state", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid state") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestGetLinkCallbackMissingState(t *testing.T) {
	// Session has no state stored -- treat as mismatch (400).
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	cookie := seedLinkSession(t, r, "u-1", "discord", "")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?code=x&state=any", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetLinkCallbackStateFromDifferentUser(t *testing.T) {
	// A different user owns the seeded state. Even with the right
	// state value, the callback must reject. The session carries
	// user=u-2 (the current viewer) while the state is bound to
	// u-1 (the user who started the flow).
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-2"})
		s.Set(linkStateKey("discord"), "shared-state")
		s.Set(linkStateKey("discord")+"_user", "u-1")
		_ = s.Save()
	})
	cookie := rec.Result().Header.Get("Set-Cookie")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?code=x&state=shared-state", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "session user") {
		t.Errorf("body = %q, want 'session user' hint", w.Body.String())
	}
}

func TestGetLinkCallbackMissingCode(t *testing.T) {
	_, cfg := linkFakeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := newAuthTestRouterWithLinkOAuth(t, &auth.FakeAuthClient{}, cfg, nil, nil)
	cookie := seedLinkSession(t, r, "u-1", "discord", "state-x")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?state=state-x", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetLinkCallbackDiscordSuccess(t *testing.T) {
	var (
		gotLink     *proto.LinkCredentialRequest
		gotAvatar   *proto.UpdateUserAuthRequest
		userinfoHit bool
	)
	userinfo := func(w http.ResponseWriter, r *http.Request) {
		userinfoHit = true
		if got := r.Header.Get("Authorization"); got != "Bearer fake-token" {
			t.Errorf("Authorization = %q, want 'Bearer fake-token'", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "12345",
			"username": "alice",
			"discriminator": "0",
			"avatar": "abc123"
		}`))
	}
	ts, cfg := linkFakeServer(t, userinfo)
	fake := &auth.FakeAuthClient{
		OnLinkCredential: func(in *proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			gotLink = in
			return &proto.LinkCredentialResponse{
				Credential: &proto.Credential{Id: "c-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_DISCORD},
			}, nil
		},
		OnUpdateUserAuth: func(in *proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error) {
			gotAvatar = in
			return &proto.UpdateUserAuthResponse{}, nil
		},
	}
	// Redirect the controller's userinfo URL at the mock server.
	r := newAuthTestRouterWithLinkOAuth(t, fake, cfg, nil, func(ac *AuthController) {
		ac.DiscordUserinfoURL = ts.URL + "/userinfo"
	})
	cookie := seedLinkSession(t, r, "u-1", "discord", "state-1")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?code=auth-code&state=state-1", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307. body=%s", w.Code, w.Body.String())
	}
	if !userinfoHit {
		t.Error("userinfo endpoint was not hit")
	}
	if gotLink == nil {
		t.Fatal("LinkCredential was not called")
	}
	if gotLink.UserId != "u-1" || gotLink.RequesterId != "u-1" {
		t.Errorf("user/requester = (%q, %q), want u-1/u-1", gotLink.UserId, gotLink.RequesterId)
	}
	if gotLink.Kind != proto.CredentialKind_CREDENTIAL_KIND_DISCORD {
		t.Errorf("kind = %v, want DISCORD", gotLink.Kind)
	}
	if gotLink.GetDiscordId() != "12345" {
		t.Errorf("discord_id = %q, want 12345", gotLink.GetDiscordId())
	}
	if gotAvatar == nil {
		t.Fatal("UpdateUserAuth (avatar refresh) was not called")
	}
	if set := gotAvatar.GetAvatarUrlSet(); set == "" {
		t.Errorf("avatar URL not set; change = %v", gotAvatar.AvatarUrlChange)
	} else if !strings.Contains(set, "12345") || !strings.Contains(set, "abc123") {
		t.Errorf("avatar URL = %q, want it to include id 12345 and hash abc123", set)
	}

	// Redirect target is `/complete?payload=...`. Decode the
	// payload and verify it carries the linked Discord profile.
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/api/auth/link/discord/complete?payload=") {
		t.Fatalf("Location = %q, want /complete prefix", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	decoded, ok := decodeLinkPayload(u.Query().Get("payload"))
	if !ok {
		t.Fatal("payload was not decodable")
	}
	if decoded["provider"] != "discord" {
		t.Errorf("provider = %v, want discord", decoded["provider"])
	}
	if decoded["id"] != "12345" {
		t.Errorf("id = %v, want 12345", decoded["id"])
	}
	if decoded["username"] != "alice" {
		t.Errorf("username = %v, want alice", decoded["username"])
	}
	if decoded["avatar"] != "abc123" {
		t.Errorf("avatar = %v, want abc123", decoded["avatar"])
	}
}

func TestGetLinkCallbackDiscordLinkError(t *testing.T) {
	// If LinkCredential fails (e.g. already exists), the
	// callback still serves the complete page with an error
	// payload so the SPA can react.
	userinfo := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": "12345", "username": "alice", "avatar": "abc"}`))
	}
	ts, cfg := linkFakeServer(t, userinfo)
	fake := &auth.FakeAuthClient{
		OnLinkCredential: func(*proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "already linked")
		},
	}
	r := newAuthTestRouterWithLinkOAuth(t, fake, cfg, nil, func(ac *AuthController) {
		ac.DiscordUserinfoURL = ts.URL + "/userinfo"
	})
	cookie := seedLinkSession(t, r, "u-1", "discord", "state-1")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/discord/callback?code=x&state=state-1", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", w.Code)
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	decoded, ok := decodeLinkPayload(u.Query().Get("payload"))
	if !ok {
		t.Fatal("payload was not decodable")
	}
	if _, hasErr := decoded["error"]; !hasErr {
		t.Errorf("payload missing error key: %+v", decoded)
	}
	if decoded["provider"] != "discord" {
		t.Errorf("provider = %v, want discord", decoded["provider"])
	}
}

func TestGetLinkCallbackGoogleSuccess(t *testing.T) {
	var (
		gotLink   *proto.LinkCredentialRequest
		gotAvatar *proto.UpdateUserAuthRequest
	)
	userinfo := func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fake-token" {
			t.Errorf("Authorization = %q, want 'Bearer fake-token'", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sub": "google-sub-1",
			"email": "alice@example.com",
			"email_verified": true,
			"name": "Alice",
			"picture": "https://example.com/p.png"
		}`))
	}
	ts, cfg := linkFakeServer(t, userinfo)
	fake := &auth.FakeAuthClient{
		OnLinkCredential: func(in *proto.LinkCredentialRequest) (*proto.LinkCredentialResponse, error) {
			gotLink = in
			return &proto.LinkCredentialResponse{
				Credential: &proto.Credential{Id: "c-1", Kind: proto.CredentialKind_CREDENTIAL_KIND_GOOGLE},
			}, nil
		},
		OnUpdateUserAuth: func(in *proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error) {
			gotAvatar = in
			return &proto.UpdateUserAuthResponse{}, nil
		},
	}
	r := newAuthTestRouterWithLinkOAuth(t, fake, nil, cfg, func(ac *AuthController) {
		ac.GoogleUserinfoURL = ts.URL + "/userinfo"
	})
	cookie := seedLinkSession(t, r, "u-1", "google", "state-1")

	req := httptest.NewRequest(http.MethodGet, "/auth/link/google/callback?code=x&state=state-1", nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", w.Code)
	}
	if gotLink == nil {
		t.Fatal("LinkCredential was not called")
	}
	if gotLink.Kind != proto.CredentialKind_CREDENTIAL_KIND_GOOGLE {
		t.Errorf("kind = %v, want GOOGLE", gotLink.Kind)
	}
	if gotLink.GetGoogleId() != "google-sub-1" {
		t.Errorf("google_id = %q, want google-sub-1", gotLink.GetGoogleId())
	}
	if gotAvatar == nil {
		t.Fatal("UpdateUserAuth (avatar refresh) was not called")
	}
	if set := gotAvatar.GetAvatarUrlSet(); set != "https://example.com/p.png" {
		t.Errorf("avatar URL = %q, want https://example.com/p.png", set)
	}

	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	decoded, ok := decodeLinkPayload(u.Query().Get("payload"))
	if !ok {
		t.Fatal("payload was not decodable")
	}
	if decoded["provider"] != "google" {
		t.Errorf("provider = %v, want google", decoded["provider"])
	}
	if decoded["id"] != "google-sub-1" {
		t.Errorf("id = %v, want google-sub-1", decoded["id"])
	}
	if decoded["email"] != "alice@example.com" {
		t.Errorf("email = %v, want alice@example.com", decoded["email"])
	}
	if decoded["picture"] != "https://example.com/p.png" {
		t.Errorf("picture = %v, want https://example.com/p.png", decoded["picture"])
	}
}

// ---------- GetLinkComplete ----------

func TestGetLinkCompleteUnknownProvider(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/link/foo/complete?payload=anything", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetLinkCompleteMissingPayload(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/link/discord/complete", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetLinkCompleteMalformedPayload(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/link/discord/complete?payload=not-base64!@#", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetLinkCompleteServesHTML(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	encoded, err := encodeLinkPayload(map[string]any{
		"provider": "discord",
		"id":       "12345",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	w := doRequest(r, http.MethodGet, "/auth/link/discord/complete?payload="+encoded, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "postMessage") {
		t.Errorf("body does not include postMessage call: %s", body)
	}
	if !strings.Contains(body, "http://localhost:5173") {
		t.Errorf("body does not include configured frontend origin: %s", body)
	}
	if !strings.Contains(body, "auth-link-complete") {
		t.Errorf("body does not include the postMessage event tag: %s", body)
	}
}

// ---------- Logout ----------

func TestLogout(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodGet, "/auth/logout", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ---------- Helpers ----------

// runWithSession injects the session middleware on a single request
// so handler code that uses `sessions.Default(c)` can find the
// session store. The done callback is invoked with the c populated;
// the test then re-issues its request with the cookie.
//
// The request is rewritten to hit `/__set_session` so the route
// doesn't fall through to anything that requires the session to be
// already populated.
func runWithSession(req *http.Request, rec *httptest.ResponseRecorder, r *gin.Engine, done func(c *gin.Context)) *httptest.ResponseRecorder {
	// Inject a temporary route that sets the session and returns.
	r.GET("/__set_session", func(c *gin.Context) {
		done(c)
		c.Status(http.StatusOK)
	})
	setupReq := httptest.NewRequest(http.MethodGet, "/__set_session", nil)
	r.ServeHTTP(rec, setupReq)
	return rec
}

// fakeAuthClient is the test fake for the auth service. The default
// value is a zero-value struct that errors on every method call,
// which is useful for tests that don't expect any gRPC traffic.
type fakeAuthClient = auth.AuthServiceClientIface

// fakeAuth returns a fresh fakeAuthClient. The default fake errors
// on every method call. Tests that need a working fake should use
// the auth.FakeAuthClientForTesting helper from src/auth/fake.go
// (added in this commit).
func fakeAuth() fakeAuthClient {
	// Re-export the auth-package fake so test code reads naturally.
	// We avoid spreading the fake definition across packages by
	// calling a constructor that returns the same zero-value
	// default. The zero value satisfies the interface but every
	// method returns (nil, errors.New("not configured")) -- which is
	// exactly what tests that don't configure gRPC want.
	return nil
}

// newFakeClient returns a configured FakeAuthClient for tests that
// need to work with the gRPC layer. The returned fake is wrapped in
// the interface so it can be passed to NewAuthController.
func newFakeClient() *auth.FakeAuthClient {
	return &auth.FakeAuthClient{}
}

// ---------- Passkey ceremony endpoints ----------
//
// The test router wires AuthController with the WebAuthn instance
// left nil, so the four anonymous endpoints must short-circuit with
// 503 ("Passkey support is not configured"). The two link endpoints
// also check the session before the WebAuthn call and surface 401
// for unauthenticated callers.

func TestPostPasskeyRegisterBeginNotConfigured(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/passkey/register/begin", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "WEBAUTHN_RP_ID") {
		t.Errorf("body = %q, want 'WEBAUTHN_RP_ID' hint", w.Body.String())
	}
}

func TestPostPasskeyRegisterFinishNotConfigured(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/passkey/register/finish", PasskeyCeremonyFinishRequest{})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestPostPasskeyLoginBeginNotConfigured(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/passkey/login/begin", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestPostPasskeyLoginFinishNotConfigured(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/passkey/login/finish", PasskeyCeremonyFinishRequest{})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestPostLinkPasskeyBeginNotLoggedIn(t *testing.T) {
	// Link endpoints sit behind the session middleware. Without
	// a session the controller returns 401 before reaching the
	// WebAuthn gate.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/link/passkey/begin", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestPostLinkPasskeyFinishNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/link/passkey/finish", PasskeyCeremonyFinishRequest{})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestPostLinkPasskeyBeginLoggedInButNotConfigured(t *testing.T) {
	// Logged-in caller still hits 503 because the test router
	// does not configure WebAuthn. The session check passes; the
	// WebAuthn gate fires next.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/passkey/begin", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestPostLinkPasskeyBeginPopulatesUserHandle(t *testing.T) {
	// On the success path the controller lifts `user_id` and
	// `user_name` to the top level so the frontend does not have
	// to dig into the nested options or hit a client-side cache.
	// `user_id` must be base64url(no padding) of the raw id bytes,
	// matching the encoding go-webauthn uses inside options.user.id.
	const userID = "0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"
	fake := &auth.FakeAuthClient{
		OnGetUserAuth: func(*proto.GetUserAuthRequest) (*proto.GetUserAuthResponse, error) {
			return &proto.GetUserAuthResponse{
				User: &proto.UserAuth{
					Id:       userID,
					Username: "alice",
					Email:    "alice@example.com",
				},
			}, nil
		},
		OnListPasskeys: func(*proto.ListPasskeysRequest) (*proto.ListPasskeysResponse, error) {
			return &proto.ListPasskeysResponse{}, nil
		},
	}
	r := newAuthTestRouterWithLinkOAuth(t, fake, nil, nil, func(ac *AuthController) {
		w, err := webauthn.New(&webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test RP",
			RPOrigins:     []string{"http://localhost"},
		})
		if err != nil {
			t.Fatalf("webauthn.New: %v", err)
		}
		ac.webauthn = w
	})

	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: userID, Email: "alice@example.com"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/passkey/begin", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantUserID := base64.RawURLEncoding.EncodeToString([]byte(userID))
	if got["user_id"] != wantUserID {
		t.Errorf("user_id = %v, want %s", got["user_id"], wantUserID)
	}
	if got["user_name"] != "alice" {
		t.Errorf("user_name = %v, want alice", got["user_name"])
	}
	if _, ok := got["session_key"].(string); !ok {
		t.Errorf("session_key missing or non-string: %v", got["session_key"])
	}
	if got["options"] == nil {
		t.Errorf("options missing in response: %v", got)
	}
	// Sanity: the nested options block also carries the same user.id
	// the top-level field promises. The frontend can read either; the
	// top-level field is the cache-bypass path.
	opts, _ := got["options"].(map[string]any)
	if opts != nil {
		if userBlock, ok := opts["user"].(map[string]any); ok {
			if userBlock["id"] != wantUserID {
				t.Errorf("options.user.id = %v, want %s (must match top-level user_id)", userBlock["id"], wantUserID)
			}
			if userBlock["name"] != "alice" {
				t.Errorf("options.user.name = %v, want alice", userBlock["name"])
			}
		} else {
			t.Errorf("options.user block missing: %v", opts)
		}
	}
}

// TestPostLinkPasskeyBeginLiftsChallenge asserts `challenge` is at
// the top level of /auth/link/passkey/begin. The frontend may read
// `data.challenge` directly (e.g. when feeding it to a custom
// publicKey builder) without digging into `data.options`.
func TestPostLinkPasskeyBeginLiftsChallenge(t *testing.T) {
	const userID = "0195f8f4-1167-7f89-b5ec-b40a8f08f4cb"
	fake := &auth.FakeAuthClient{
		OnGetUserAuth: func(*proto.GetUserAuthRequest) (*proto.GetUserAuthResponse, error) {
			return &proto.GetUserAuthResponse{
				User: &proto.UserAuth{Id: userID, Username: "alice", Email: "alice@example.com"},
			}, nil
		},
		OnListPasskeys: func(*proto.ListPasskeysRequest) (*proto.ListPasskeysResponse, error) {
			return &proto.ListPasskeysResponse{}, nil
		},
	}
	r := newAuthTestRouterWithLinkOAuth(t, fake, nil, nil, func(ac *AuthController) {
		w, err := webauthn.New(&webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test RP",
			RPOrigins:     []string{"http://localhost"},
		})
		if err != nil {
			t.Fatalf("webauthn.New: %v", err)
		}
		ac.webauthn = w
	})

	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: userID, Email: "alice@example.com"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/link/passkey/begin", nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	gotChallenge, ok := got["challenge"].(string)
	if !ok || gotChallenge == "" {
		t.Fatalf("top-level challenge missing or empty: %v", got["challenge"])
	}
	opts, _ := got["options"].(map[string]any)
	if opts == nil {
		t.Fatalf("options missing: %+v", got)
	}
	if opts["challenge"] != gotChallenge {
		t.Errorf("options.challenge (%v) and top-level challenge (%v) must match",
			opts["challenge"], gotChallenge)
	}
}

func TestPostPasskeyRegisterFinishRequiresExistingUser(t *testing.T) {
	// /register/finish with no WebAuthn config still surfaces 503.
	// The "ceremony did not include a user id" 400 branch only
	// fires once WebAuthn is configured; that path is covered by
	// the integration tests wired up under test/. Unit tests
	// stay at the 503 gate.
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	body, _ := json.Marshal(PasskeyCeremonyFinishRequest{SessionKey: "any"})
	w := doRequest(r, http.MethodPost, "/auth/passkey/register/finish", body)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// TestPasskeyBeginLiftsChallenge registers a third test against
// /auth/passkey/register/begin and /auth/passkey/login/begin to
// confirm the anonymous endpoints also lift `challenge` to the top
// level. /link/passkey/begin is covered by
// TestPostLinkPasskeyBeginLiftsChallenge above.
func TestPasskeyBeginAnonymousLiftChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	r.Use(sessions.Sessions("discord_auth", store))
	wInst, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"http://localhost"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	ac := NewAuthController(nil, nil, &auth.FakeAuthClient{}, nil, "test-jwt-secret",
		"", "", nil, nil, nil)
	ac.webauthn = wInst
	g := r.Group("/auth")
	g.POST("/passkey/register/begin", ac.PostPasskeyRegisterBegin)
	g.POST("/passkey/login/begin", ac.PostPasskeyLoginBegin)

	for _, path := range []string{"/auth/passkey/register/begin", "/auth/passkey/login/begin"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body=%s", path, w.Code, w.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s unmarshal: %v", path, err)
		}
		if _, ok := got["challenge"].(string); !ok {
			t.Errorf("%s missing top-level challenge: %+v", path, got)
		}
	}
}

// keep `errors` and `status` imports referenced in case the test
// file grows below.
var _ = errors.New
var _ = status.Code
var _ = codes.OK

// ---------- PostUser / PatchUser (REST CRUD on /api/users) ----------

func TestPostUserMissingFields(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/api/users", PostUserRequest{Email: "a@b"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPostUserSuccess(t *testing.T) {
	var captured *proto.CreateUserAuthRequest
	fake := &auth.FakeAuthClient{
		OnCreateUserAuth: func(in *proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			captured = in
			return &proto.CreateUserAuthResponse{
				User: &proto.UserAuth{Id: "u-1", Email: in.Email, Username: in.Username, AvatarUrl: in.AvatarUrl},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/api/users", PostUserRequest{
		Email:    "alice@example.com",
		Username: "alice",
		Password: "anything",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if captured == nil {
		t.Fatalf("CreateUserAuth was not called")
	}
	if captured.Email != "alice@example.com" || captured.Username != "alice" {
		t.Errorf("captured email/username mismatch: %+v", captured)
	}
	if captured.PasswordHash == "" {
		t.Error("server hash was empty")
	}
	if captured.PasswordHash == "anything" {
		t.Error("plaintext password leaked to gRPC")
	}
	ok, err := (auth.Argon2Hasher{}).Verify("anything", captured.PasswordHash)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("server hash did not reproduce plaintext")
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["id"] != "u-1" {
		t.Errorf("id = %v, want u-1", got["id"])
	}
}

func TestPostUserEmailConflict(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnCreateUserAuth: func(*proto.CreateUserAuthRequest) (*proto.CreateUserAuthResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "email taken")
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/api/users", PostUserRequest{
		Email:    "alice@example.com",
		Username: "alice",
		Password: "anything",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestPatchUserUnauthenticated(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	// PATCH requires a session cookie; without one the controller
	// returns 401 before reaching the gRPC layer.
	req := httptest.NewRequest(http.MethodPatch, "/api/users/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestPatchUserInvalidID(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	// Bad UUID in :id is rejected before auth runs, but we still
	// need a session so the auth middleware does not shortcut us.
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	req := httptest.NewRequest(http.MethodPatch, "/api/users/not-a-uuid", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPatchUserSetAndClearRejected(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	body := []byte(`{"username":"alice","username_clear":true}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/users/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPatchUserSuccess(t *testing.T) {
	var captured *proto.UpdateUserAuthRequest
	fake := &auth.FakeAuthClient{
		OnUpdateUserAuth: func(in *proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error) {
			captured = in
			return &proto.UpdateUserAuthResponse{
				User: &proto.UserAuth{Id: in.UserId, Email: "alice@example.com", Username: "alice"},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})

	body := []byte(`{"username":"alice","avatar_url_clear":true}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/users/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if captured == nil {
		t.Fatalf("UpdateUserAuth was not called")
	}
	if captured.UserId != "0195f8f4-1167-7f89-b5ec-b40a8f08f4cb" {
		t.Errorf("user_id = %q", captured.UserId)
	}
	if captured.RequesterId != "u-1" {
		t.Errorf("requester_id = %q, want u-1", captured.RequesterId)
	}
	if set, ok := captured.UsernameChange.(*proto.UpdateUserAuthRequest_UsernameSet); !ok || set.UsernameSet != "alice" {
		t.Errorf("username oneof = %T %+v", captured.UsernameChange, captured.UsernameChange)
	}
	if _, ok := captured.AvatarUrlChange.(*proto.UpdateUserAuthRequest_AvatarUrlClear); !ok {
		t.Errorf("avatar_url oneof = %T %+v, want clear", captured.AvatarUrlChange, captured.AvatarUrlChange)
	}
	if captured.EmailChange != nil || captured.EmailVerifiedChange != nil {
		t.Errorf("untouched oneofs must stay nil, got email=%v email_verified=%v", captured.EmailChange, captured.EmailVerifiedChange)
	}
}

func TestPatchUserNotFound(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnUpdateUserAuth: func(*proto.UpdateUserAuthRequest) (*proto.UpdateUserAuthResponse, error) {
			return nil, status.Error(codes.NotFound, "no such user")
		},
	}
	r := newAuthTestRouter(t, fake)
	rec := httptest.NewRecorder()
	runWithSession(nil, rec, r, func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", models.User{ID: "u-1"})
		_ = s.Save()
	})
	body := []byte(`{"username":"alice"}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/users/0195f8f4-1167-7f89-b5ec-b40a8f08f4cb", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
