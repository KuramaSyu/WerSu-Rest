package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AccessClaims struct {
	jwt.RegisteredClaims
}

// UserFromContext retrieves the authenticated user from the request context.
// It attempts to extract user information using three methods in order:
// 1. Parses a Bearer JWT token from the Authorization header if present
// 2. Falls back to a JWT supplied via the `jwt` query parameter
// 3. Falls back to retrieving user data from the session
//
// Returns:
//   - *models.User: pointer to the authenticated user, or nil if authentication fails
//   - int: HTTP status code indicating the result (StatusOK on success, StatusUnauthorized if not logged in, StatusInternalServerError on format errors)
//   - error: descriptive error message if authentication fails, or nil on success
//
// Errors returned:
//   - "not logged in" with StatusUnauthorized when no Authorization header or valid session is found
//   - JWT-related errors from UserFromAuthJWT if Bearer token parsing fails
//   - "wrong user format" with StatusInternalServerError if session data cannot be cast to models.User
func UserFromContext(c *gin.Context) (*models.User, int, error) {
	// 1. Bearer token in the Authorization header
	if c.GetHeader("Authorization") != "" {
		user, status, err := UserFromAuthJWT(c, config.AppConfig.JwtSecret)
		if err != nil {
			return nil, status, err
		}
		return user, status, nil
	}

	// 2. JWT in the `jwt` query parameter
	if queryToken := c.Query("jwt"); queryToken != "" {
		claims, code, err := UnpackJWT(queryToken, config.AppConfig.JwtSecret)
		if err != nil {
			return nil, code, err
		}
		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			return nil, http.StatusUnauthorized, fmt.Errorf("token has expired")
		}
		return &models.User{ID: claims.Subject}, http.StatusOK, nil
	}

	// 3. session-based authentication
	session := sessions.Default(c)
	userData := session.Get("user")
	if userData == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("not logged in")
	}

	grpc_user, ok := userData.(models.User)
	if !ok {
		return nil, http.StatusInternalServerError, fmt.Errorf("wrong user format: %v %v", userData, ok)
	}

	return &grpc_user, http.StatusOK, nil
}

// UserFromAuthJWT extracts and validates a JWT token from the Authorization header of a Gin context.
// It verifies the header format (Bearer token), unpacks the JWT, and checks token expiration.
// Returns a User struct with the subject ID from the token claims, HTTP status code, and error.
// Returns http.StatusBadRequest if the Authorization header is missing or malformed,
// http.StatusUnauthorized if the token has expired, or http.StatusOK on success.
func UserFromAuthJWT(c *gin.Context, jwtSecret string) (*models.User, int, error) {
	// check auth header format
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid Authorization header format. Expected 'Bearer <token>'")
	}

	// unpack token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	jwtClaims, code, err := UnpackJWT(tokenString, jwtSecret)
	if err != nil {
		return nil, code, err
	}

	// check if token has expired
	if jwtClaims.ExpiresAt.Time.Before(time.Now()) {
		return nil, http.StatusUnauthorized, fmt.Errorf("token has expired")
	}

	return &models.User{
		ID: jwtClaims.Subject,
	}, http.StatusOK, nil

}

// UnpackJWT parses and validates a JWT token using the provided secret.
// It verifies the token's signature using HMAC (HS256) and checks token validity.
// Returns the decoded AccessClaims, an HTTP status code, and an error if parsing or validation fails.
// On success, returns the claims and http.StatusOK (0).
// On failure, returns nil claims and http.StatusUnauthorized with a descriptive error.
func UnpackJWT(token string, secret string) (*jwt.RegisteredClaims, int, error) {
	claims := &jwt.RegisteredClaims{}

	newToken, err := jwt.ParseWithClaims(
		token,
		claims,
		func(token *jwt.Token) (any, error) {
			// signature method should be HS256 -> maybe switch later to Ed25519 or RS256
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// []byte is required
			return []byte(secret), nil
		},
	)

	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	if !newToken.Valid {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid token")
	}

	return claims, http.StatusOK, nil
}

// SetGinError is a helper function that sends a JSON error response.
// It formats the error message and sets the appropriate HTTP status code.
//
// Parameters:
//   - c: The Gin context
//   - status: HTTP status code to return
//   - err: The error to send in the response body
//
// Behavior:
//   - When `status` is http.StatusInternalServerError and `err` (or any error
//     it wraps) carries a gRPC status code of Unavailable, DeadlineExceeded,
//     or ResourceExhausted, the response is automatically upgraded to
//     http.StatusServiceUnavailable (503). This lets every gRPC-calling
//     controller report a "backend down / overloaded" condition without each
//     handler having to inspect the error itself.
//   - For any other status (e.g. 400, 401, 403, 404) the response is written
//     unchanged, so the gRPC upgrade only kicks in for genuine 500 paths.
func SetGinError(c *gin.Context, status int, err error) {
	if status == http.StatusInternalServerError && isGrpcBackendUnavailable(err) {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{"error": err.Error()})

}

// isGrpcBackendUnavailable reports whether err (or any wrapped error in its
// chain) carries a gRPC status code that indicates the backend service is
// unreachable: Unavailable, DeadlineExceeded, or ResourceExhausted.
//
// Returns false for nil, for plain (non-gRPC) errors, and for any other
// gRPC status code.
func isGrpcBackendUnavailable(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	}
	return false
}

// GenerateJWT creates a new JSON Web Token (JWT) for a given user ID.
// With max_lifetime parameter, you can specify a datetime where to token will expire at latest.
// If this is more than 15 minutes in the future, it will be set to 15 minutes anyways.
// It includes the following claims:
//   - "sub" (Subject): The user ID.
//   - "exp" (Expiration Time): 15 minutes from the time of creation.
//   - "iss" (Issuer): "wersu-rest-proxy".
//   - "iat" (Issued At): The time the token was issued.
//
// Returns: token and error
func GenerateJWT(userID string, secret string, max_lifetime *time.Time) (string, error) {
	expires_at := time.Now().Add(15 * time.Minute)
	if max_lifetime != nil && max_lifetime.Before(expires_at) {
		expires_at = *max_lifetime
	}
	claims := jwt.RegisteredClaims{
		Issuer:    "wersu-rest-proxy",
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(expires_at),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)
	return token.SignedString([]byte(secret))
}

// shape of JWTs for attachments provided by the gRPC backend.
// att is the attachment id
type AttachmentAccessClaims struct {
	jwt.RegisteredClaims
	Att string `json:"att,omitempty"`
}

const AttachmentJWTIssuer = "WerSu gRPC"

var ErrAttachmentMismatch = errors.New("attachment id in JWT does not match requested key")

// UnpackAttachmentJWT parses and validates an attachment access JWT.
func UnpackAttachmentJWT(tokenString, secret string) (*AttachmentAccessClaims, int, error) {
	claims := &AttachmentAccessClaims{}
	parsed, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		},
	)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	if !parsed.Valid {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid token")
	}

	if claims.Issuer != AttachmentJWTIssuer {
		return nil, http.StatusUnauthorized, fmt.Errorf("unexpected issuer: %q", claims.Issuer)
	}

	if claims.Subject == "" {
		return nil, http.StatusUnauthorized, fmt.Errorf("token missing sub claim")
	}
	if claims.Att == "" {
		return nil, http.StatusUnauthorized, fmt.Errorf("token missing att claim")
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, http.StatusUnauthorized, fmt.Errorf("token has expired")
	}

	return claims, http.StatusOK, nil
}
