package auth

import (
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PostLogin godoc
// @Summary      Sign in with a password
// @Description  Authenticates an existing user via password. The client
// @Description  sends a plaintext password; the server hashes it
// @Description  (argon2id) before comparing to the stored hash. On
// @Description  success, a session cookie is set and the canonical
// @Description  UserAuth is returned.
// @Description
// @Description  Passkey login uses the dedicated
// @Description  /auth/passkey/login/{begin,finish} endpoints instead.
// @Description  OAuth flows (Discord, Google) keep their own
// @Description  /auth/<provider>/login routes so the browser can be
// @Description  redirected to the provider.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      LoginRequest  true  "Login payload (kind: \"password\")"
// @Success      200      {object}  models.JsUserAuth  "Login successful - session cookie set"
// @Failure      400      {object}  map[string]string   "Bad Request - Invalid body, unknown kind, or missing fields"
// @Failure      401      {object}  map[string]string   "Unauthorized - Invalid credentials"
// @Failure      500      {object}  map[string]string   "Internal Server Error - gRPC service failure"
// @Router       /api/auth/login [post]
func (ac *AuthController) PostLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	kind, ok := auth.ResolveKind(string(req.Kind))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown login kind: " + string(req.Kind)})
		return
	}

	// For signin vs signup: signup is a separate route below. Login
	// is signin only.
	var strategy auth.LoginStrategy
	switch kind {
	case auth.KindPassword:
		if req.Email == "" || req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
			return
		}
		strategy = &auth.PasswordStrategy{
			Auth:     ac.authService,
			Email:    req.Email,
			Password: req.Password,
			Signup:   false,
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Login kind requires its own route: " + string(kind)})
		return
	}

	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		if err == auth.InvalidCredentialsError {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	ac.loginUser(c, user)
}

// PostSignup godoc
// @Summary      Sign up with a password
// @Description  Creates a new user via password signup. The client
// @Description  sends a plaintext password; the server hashes it
// @Description  (argon2id) before reaching gRPC. On success, a session
// @Description  cookie is set and the canonical UserAuth is returned.
// @Description
// @Description  Returns 409 if the email is already in use.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      SignupRequest  true  "Signup payload"
// @Success      200      {object}  models.JsUserAuth  "User created and signed in - session cookie set"
// @Failure      400      {object}  map[string]string   "Bad Request - Invalid body or missing fields"
// @Failure      409      {object}  map[string]string   "Conflict - Email already in use"
// @Failure      500      {object}  map[string]string   "Internal Server Error - gRPC service failure"
// @Router       /api/auth/signup [post]
func (ac *AuthController) PostSignup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Email == "" || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, username, and password are required"})
		return
	}

	gravatarAvatar := auth.GravatarURL(req.Email)

	strategy := &auth.PasswordStrategy{
		Auth:      ac.authService,
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		Signup:    true,
		AvatarUrl: gravatarAvatar,
	}
	user, err := strategy.Login(c.Request.Context())
	if err != nil {
		// ALREADY_EXISTS on the email -> 409.
		if status.Code(err) == codes.AlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, err)
		return
	}
	ac.loginUser(c, user)
}
