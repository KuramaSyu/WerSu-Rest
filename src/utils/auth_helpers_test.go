package utils

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func init() {
	gob.Register(models.User{})
}

// testRouterWithSession returns a gin engine wired with an in-memory
// cookie session store. Two temporary routes are registered so tests
// can set up a session cookie and then call UserFromContext.
func testRouterWithSession(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("test-session-secret"))
	r.Use(sessions.Sessions("discord_auth", store))

	// route used to mint a session cookie carrying a user
	r.GET("/__set_session", func(c *gin.Context) {
		u, _ := c.Get("session_user")
		if u != nil {
			s := sessions.Default(c)
			s.Set("user", u)
			_ = s.Save()
		}
		c.Status(http.StatusOK)
	})

	// route used to exercise UserFromContext
	r.GET("/__get_user", func(c *gin.Context) {
		user, code, err := UserFromContext(c)
		out := gin.H{"code": code}
		if user != nil {
			out["id"] = user.ID
		}
		if err != nil {
			out["error"] = err.Error()
		}
		c.JSON(code, out)
	})

	return r
}

// mintSessionCookie creates a fresh in-memory session carrying the given
// user and returns the Set-Cookie header value.
func mintSessionCookie(t *testing.T, r *gin.Engine, user models.User) string {
	t.Helper()
	// Create a one-off router with the same store name so the cookie
	// names match. Because the store names match, the session cookie
	// produced here is accepted by testRouterWithSession.
	setter := gin.New()
	store := cookie.NewStore([]byte("test-session-secret"))
	setter.Use(sessions.Sessions("discord_auth", store))
	setter.GET("/__set_session", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user", user)
		_ = s.Save()
		c.Status(http.StatusOK)
	})
	recSetter := httptest.NewRecorder()
	reqSetter := httptest.NewRequest(http.MethodGet, "/__set_session", nil)
	setter.ServeHTTP(recSetter, reqSetter)
	return recSetter.Result().Header.Get("Set-Cookie")
}

func setJwtSecret(t *testing.T) {
	t.Helper()
	prev := config.AppConfig
	config.AppConfig = &config.Config{JwtSecret: "test-jwt-secret"}
	t.Cleanup(func() { config.AppConfig = prev })
}

// ---------- UnpackJWT ----------

func TestUnpackJWT_RoundTrip(t *testing.T) {
	secret := "my-super-secret"
	token, err := GenerateJWT("user-42", secret, nil)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	claims, code, err := UnpackJWT(token, secret)
	if err != nil {
		t.Fatalf("UnpackJWT error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if claims.Subject != "user-42" {
		t.Errorf("subject = %q, want user-42", claims.Subject)
	}
	if claims.Issuer != "wersu-rest-proxy" {
		t.Errorf("issuer = %q, want wersu-rest-proxy", claims.Issuer)
	}
}

func TestUnpackJWT_BadSecret(t *testing.T) {
	secret := "signer-secret"
	token, _ := GenerateJWT("user-1", secret, nil)

	_, code, err := UnpackJWT(token, "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestUnpackJWT_Expired(t *testing.T) {
	secret := "signer-secret"
	// Token expired 1 hour ago
	past := time.Now().Add(-time.Hour)
	token, _ := GenerateJWT("user-1", secret, &past)

	claims, code, err := UnpackJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	// Expired tokens still parse; the caller checks ExpiresAt.
	// Our implementation returns the claims and lets the caller
	// decide. But UnpackJWT only returns claims when valid.
	// Wait, actually jwt.ParseWithClaims returns error for expired token.
	// So claims might be nil. We don't check claims further.
	_ = claims
}

func TestUnpackJWT_Malformed(t *testing.T) {
	_, code, err := UnpackJWT("not.a.jwt", "secret")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestUnpackJWT_WrongSigningMethod(t *testing.T) {
	// Build a token with a none alg to bypass signature check;
	// jwt.ParseWithClaims should reject it.
	// This is hard to trigger with the helper, so we rely on ParseWithClaims
	// internals. Instead we construct a raw token.
	raw := jwtBuilderNone("sub", "user-1")
	_, code, err := UnpackJWT(raw, "secret")
	if err == nil {
		t.Fatal("expected error for none signing method")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// ---------- UserFromAuthJWT ----------

func TestUserFromAuthJWT_Valid(t *testing.T) {
	setJwtSecret(t)
	token, _ := GenerateJWT("user-99", config.AppConfig.JwtSecret, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	user, code, err := UserFromAuthJWT(c, config.AppConfig.JwtSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if user.ID != "user-99" {
		t.Errorf("id = %q, want user-99", user.ID)
	}
}

func TestUserFromAuthJWT_MissingHeader(t *testing.T) {
	setJwtSecret(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	_, code, err := UserFromAuthJWT(c, config.AppConfig.JwtSecret)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(err.Error(), "missing Authorization header") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUserFromAuthJWT_NotBearer(t *testing.T) {
	setJwtSecret(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	_, code, err := UserFromAuthJWT(c, config.AppConfig.JwtSecret)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(err.Error(), "Bearer") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUserFromAuthJWT_Expired(t *testing.T) {
	setJwtSecret(t)
	past := time.Now().Add(-time.Hour)
	token, _ := GenerateJWT("user-1", config.AppConfig.JwtSecret, &past)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	_, code, err := UserFromAuthJWT(c, config.AppConfig.JwtSecret)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------- UserFromContext : session cookie ----------

func TestUserFromContext_SessionCookie(t *testing.T) {
	setJwtSecret(t)
	r := testRouterWithSession(t)
	cookieVal := mintSessionCookie(t, r, models.User{ID: "session-user"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/__get_user", nil)
	req.Header.Set("Cookie", cookieVal)
	r.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if body["id"] != "session-user" {
		t.Errorf("id = %v, want session-user", body["id"])
	}
}

func TestUserFromContext_NoAuth(t *testing.T) {
	setJwtSecret(t)
	r := testRouterWithSession(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/__get_user", nil)
	r.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(body["error"].(string), "not logged in") {
		t.Errorf("expected 'not logged in', got %v", body["error"])
	}
}

// ---------- UserFromContext : JWT query param ----------

func TestUserFromContext_QueryJWT(t *testing.T) {
	setJwtSecret(t)
	token, _ := GenerateJWT("jwt-query-user", config.AppConfig.JwtSecret, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?jwt="+token, nil)

	user, code, err := UserFromContext(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if user.ID != "jwt-query-user" {
		t.Errorf("id = %q, want jwt-query-user", user.ID)
	}
}

func TestUserFromContext_QueryJWT_Expired(t *testing.T) {
	setJwtSecret(t)
	past := time.Now().Add(-time.Hour)
	token, _ := GenerateJWT("jwt-query-user", config.AppConfig.JwtSecret, &past)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?jwt="+token, nil)

	_, code, err := UserFromContext(c)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUserFromContext_QueryJWT_Invalid(t *testing.T) {
	setJwtSecret(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?jwt=badtoken", nil)

	_, code, err := UserFromContext(c)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if err == nil {
		t.Fatal("expected error for invalid query jwt")
	}
}

// ---------- UserFromContext : Bearer header ----------

func TestUserFromContext_BearerHeader(t *testing.T) {
	setJwtSecret(t)
	token, _ := GenerateJWT("bearer-user", config.AppConfig.JwtSecret, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	user, code, err := UserFromContext(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if user.ID != "bearer-user" {
		t.Errorf("id = %q, want bearer-user", user.ID)
	}
}

func TestUserFromContext_BearerHeader_Malformed(t *testing.T) {
	setJwtSecret(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	_, code, err := UserFromContext(c)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(err.Error(), "Bearer") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------- UserFromContext : priority ----------

func TestUserFromContext_HeaderBeatsQueryAndSession(t *testing.T) {
	setJwtSecret(t)

	// Header carries bearer-user, query carries query-user.
	bearerToken, _ := GenerateJWT("bearer-user", config.AppConfig.JwtSecret, nil)
	queryToken, _ := GenerateJWT("query-user", config.AppConfig.JwtSecret, nil)

	// Build a router with session so the session path is available.
	r := testRouterWithSession(t)
	cookieVal := mintSessionCookie(t, r, models.User{ID: "session-user"})

	req := httptest.NewRequest(http.MethodGet, "/__get_user?jwt="+queryToken, nil)
	req.Header.Set("Cookie", cookieVal)
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var body map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["id"] != "bearer-user" {
		t.Errorf("id = %v, want bearer-user (header should win)", body["id"])
	}
}

func TestUserFromContext_QueryBeatsSession(t *testing.T) {
	setJwtSecret(t)

	queryToken, _ := GenerateJWT("query-user", config.AppConfig.JwtSecret, nil)

	r := testRouterWithSession(t)
	cookieVal := mintSessionCookie(t, r, models.User{ID: "session-user"})

	req := httptest.NewRequest(http.MethodGet, "/__get_user?jwt="+queryToken, nil)
	req.Header.Set("Cookie", cookieVal)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var body map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["id"] != "query-user" {
		t.Errorf("id = %v, want query-user (query should win over session)", body["id"])
	}
}

// jwtBuilderNone returns an alg=none JWT with the given subject.
// Used only to test rejection of unexpected signing methods.
func jwtBuilderNone(name, value string) string {
	// "none" JWT: header {"alg":"none","typ":"JWT"}, payload {name:value}, empty sig
	header := base64EncodeJSON(`{"alg":"none","typ":"JWT"}`)
	payload := base64EncodeJSON(`{"` + name + `":"` + value + `"}`)
	return header + "." + payload + "."
}

func base64EncodeJSON(s string) string {
	return strings.TrimRight(
		strings.NewReplacer("+", "-", "/", "_").Replace(
			base64RawEncode([]byte(s)),
		), "=",
	)
}

func base64RawEncode(b []byte) string {
	// Simple base64url raw encoding
	enc := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(enc, b)
	return string(enc)
}

var _ = json.Marshal // make sure json is used
