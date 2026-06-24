package controllers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AccessClaims struct {
	jwt.RegisteredClaims
}

// UserFromContext retrieves the authenticated user from the request context.
// It attempts to extract user information using two methods in order:
// 1. Parses a Bearer JWT token from the Authorization header if present
// 2. Falls back to retrieving user data from the session
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
	// 1. check for a Bearer token in the Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// If the Authorization header is present, attempt to parse the JWT token
		// get secret from global config - not a good pattern, but I don't want to
		// pass the secret through every controller or method
		secret := config.AppConfig.JwtSecret
		user, status, err := UserFromAuthJWT(c, secret)
		if err != nil {
			return nil, status, err
		}
		return user, status, nil
	}

	// 2. fallback to session-based authentication
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
			return secret, nil
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
func SetGinError(c *gin.Context, status int, err error) {
	c.JSON(status, gin.H{"error": err.Error()})

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
