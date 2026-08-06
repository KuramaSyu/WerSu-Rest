package controllers

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
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
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	r.Use(sessions.Sessions("discord_auth", store))

	ac := NewAuthController(
		nil, // discord OAuth config not used in these tests
		nil, // google OAuth config not used
		fake,
		nil, // shareService not used
		"test-jwt-secret",
	)
	t.Cleanup(func() { _ = ac })

	authGroup := r.Group("/auth")
	authGroup.POST("/login", ac.PostLogin)
	authGroup.POST("/signup", ac.PostSignup)
	authGroup.GET("/user", ac.GetUser)
	authGroup.GET("/me/credentials", ac.GetLinkedCredentials)
	authGroup.POST("/link/discord", ac.PostLinkDiscord)
	authGroup.POST("/link/google", ac.PostLinkGoogle)
	authGroup.POST("/link/password", ac.PostLinkPassword)
	authGroup.GET("/logout", ac.Logout)
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
	// error propagates and `SetGinError` decides the HTTP status.
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
		Password: "wrong",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid email or password") {
		t.Errorf("body = %q, want generic error", w.Body.String())
	}
}

func TestPostLoginPasswordSuccess(t *testing.T) {
	fake := &auth.FakeAuthClient{
		OnFindCredentialByProv: func(in *proto.FindCredentialByProviderRequest) (*proto.FindCredentialByProviderResponse, error) {
			// Pretend the user exists and the password matched.
			// The strategy internally hashes; for this test we
			// just return success.
			_ = in
			hash, _ := (auth.Argon2Hasher{}).Hash("realpw")
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

func TestPostLoginPasskeyNotYetImplemented(t *testing.T) {
	// The gRPC backend doesn't have VerifyPasskey yet. The strategy
	// returns a clear error and the controller maps it to 500.
	// The fake has to simulate a successful FindPasskey so the
	// strategy gets past the lookup and into the not-implemented
	// branch.
	fake := &auth.FakeAuthClient{
		OnFindPasskey: func(in *proto.FindPasskeyRequest) (*proto.FindPasskeyResponse, error) {
			return &proto.FindPasskeyResponse{
				Passkey: &proto.Passkey{
					Id:        "pk-1",
					UserId:    "u-1",
					PublicKey: []byte("pk"),
				},
			}, nil
		},
	}
	r := newAuthTestRouter(t, fake)
	w := doRequest(r, http.MethodPost, "/auth/login", LoginRequest{
		Kind:              auth.KindPasskeyKind,
		CredentialId:      []byte("cred"),
		ClientDataJSON:    []byte("cd"),
		AuthenticatorData: []byte("ad"),
		Signature:         []byte("sig"),
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (passkey not implemented)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "VerifyPasskey") {
		t.Errorf("body = %q, want mention of VerifyPasskey", w.Body.String())
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

// ---------- PostLinkPassword ----------

func TestPostLinkPasswordNotLoggedIn(t *testing.T) {
	r := newAuthTestRouter(t, &auth.FakeAuthClient{})
	w := doRequest(r, http.MethodPost, "/auth/link/password", LinkPasswordRequest{Password: "new"})
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

	// Repackage the request body and the cookie.
	body, _ := json.Marshal(LinkPasswordRequest{Password: "newpw"})
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
	if linked.GetPasswordHash() == "newpw" {
		t.Errorf("plaintext password was sent to gRPC")
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

// keep `errors` and `status` imports referenced in case the test
// file grows below.
var _ = errors.New
var _ = status.Code
var _ = codes.OK
