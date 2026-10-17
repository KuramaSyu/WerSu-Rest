package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

// PostPasskeyRegisterBegin godoc
// @Summary      Begin a passkey registration ceremony
// @Description  Starts a WebAuthn registration ceremony for a new passkey.
// @Description
// @Description  The server generates a random challenge and returns the
// @Description  ceremony options (`PublicKeyCredentialCreationOptions`) that
// @Description  the browser uses to invoke the platform authenticator. The
// @Description  challenge is stored server-side and must be presented to
// @Description  the matching `/finish` endpoint for verification.
// @Description
// @Description  Returns 503 if passkey support is not configured
// @Description  (`WEBAUTHN_RP_ID` unset).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  PasskeyCeremonyBeginReply  "WebAuthn registration options"
// @Failure      400  {object}  map[string]string          "Bad Request - Invalid request body"
// @Failure      503  {object}  map[string]string          "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/register/begin [post]
func (ac *AuthController) PostPasskeyRegisterBegin(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyBeginRequest
	_ = c.ShouldBindJSON(&req) // body is optional
	user := &proto.UserAuth{Id: req.UserId}
	wu := auth.NewWebAuthnUser(user, nil)

	log.Printf("passkey: begin register userID=%q", req.UserId)
	options, sessionData, err := ac.webauthn.BeginRegistration(wu)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("begin registration: %w", err))
		return
	}
	key, err := ac.putCeremony(*sessionData)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("store ceremony: %w", err))
		return
	}
	c.JSON(http.StatusOK, beginReplyFrom(key, options.Response))
}

// PostPasskeyRegisterFinish godoc
// @Summary      Finish a passkey registration ceremony
// @Description  Completes a WebAuthn registration ceremony started by
// @Description  `/auth/passkey/register/begin`.
// @Description
// @Description  The browser posts the attestation response
// @Description  (`credential_id`, `client_data_json`, `authenticator_data`,
// @Description  `signature`) and the `session_key` from the matching /begin.
// @Description  The server verifies the challenge, origin, RP ID, and
// @Description  attestation signature, then persists the credential via
// @Description  `AuthService.RegisterPasskey`. The User Handle supplied at
// @Description  /begin must already exist (see PostPasskeyRegisterBegin).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      PasskeyCeremonyFinishRequest  true  "WebAuthn attestation response"
// @Success      200      {object}  PasskeyCeremonyFinishReply   "Passkey registered"
// @Failure      400      {object}  map[string]string            "Bad Request - Invalid request body or expired ceremony"
// @Failure      401      {object}  map[string]string            "Unauthorized - Challenge mismatch or invalid attestation"
// @Failure      503      {object}  map[string]string            "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/register/finish [post]
func (ac *AuthController) PostPasskeyRegisterFinish(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	log.Printf("passkey: finish register session_key=%s cred_id=%s", req.SessionKey, req.Credential.ID)
	if req.SessionKey == "" {
		utils.SetGinError(c, http.StatusBadRequest, errors.New("session_key is required"))
		return
	}
	if err := validateCeremonyCredential(req.Credential); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}
	if err := withRequestBodyJSON(c, req.Credential); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("rebuild request body: %w", err))
		return
	}
	sessionData, err := ac.takeCeremony(req.SessionKey)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}
	userId := string(sessionData.UserID)
	if userId == "" || userId == "anonymous" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ceremony did not include a user id; use /auth/signup + /auth/link/passkey/{begin,finish} for first-time users"})
		return
	}
	wu, err := auth.LoadPasskeyUser(c.Request.Context(), ac.authService, userId)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("load user: %w", err))
		return
	}
	cred, err := ac.webauthn.FinishRegistration(wu, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("registration failed: %v", err)})
		return
	}
	if _, err := ac.authService.RegisterPasskey(c.Request.Context(), &proto.RegisterPasskeyRequest{
		UserId:         userId,
		RequesterId:    userId,
		CredentialId:   cred.ID,
		PublicKey:      cred.PublicKey,
		Transports:     authTransports(cred.Transport),
		Aaguid:         cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		UserVerified:   cred.Flags.UserVerified,
		FriendlyName:   req.FriendlyName,
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("register passkey: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyFinishReply{
		CredentialId: base64.RawURLEncoding.EncodeToString(cred.ID),
	})
}

// PostPasskeyLoginBegin godoc
// @Summary      Begin a passkey login ceremony
// @Description  Starts a WebAuthn assertion (login) ceremony.
// @Description
// @Description  The server generates a random challenge and returns the
// @Description  ceremony options (`PublicKeyCredentialRequestOptions`) for
// @Description  the browser. The challenge is stored server-side and must
// @Description  be presented to the matching `/finish` endpoint for
// @Description  verification. The flow is discoverable (no user identity
// @Description  required up front) -- the browser's authenticator selects
// @Description  which passkey to use and the User Handle is supplied with
// @Description  the assertion.
// @Description
// @Description  Returns 503 if passkey support is not configured.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  PasskeyCeremonyBeginReply  "WebAuthn assertion options"
// @Failure      503  {object}  map[string]string          "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/login/begin [post]
func (ac *AuthController) PostPasskeyLoginBegin(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	log.Printf("passkey: begin login (discoverable)")
	options, sessionData, err := ac.webauthn.BeginDiscoverableLogin()
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("begin login: %w", err))
		return
	}
	key, err := ac.putCeremony(*sessionData)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("store ceremony: %w", err))
		return
	}
	c.JSON(http.StatusOK, beginReplyFrom(key, options.Response))
}

// PostPasskeyLoginFinish godoc
// @Summary      Finish a passkey login ceremony
// @Description  Completes a WebAuthn assertion (login) ceremony started by
// @Description  `/auth/passkey/login/begin`.
// @Description
// @Description  The browser posts the assertion (`credential_id`,
// @Description  `client_data_json`, `authenticator_data`, `signature`) and
// @Description  the `session_key` from the matching /begin. The server
// @Description  resolves the user from the User Handle, verifies the
// @Description  signature against the stored public key, bumps the sign
// @Description  counter via `AuthService.UpdatePasskeyCounter`, and logs
// @Description  the user in.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        payload  body      PasskeyCeremonyFinishRequest  true  "WebAuthn assertion response"
// @Success      200      {object}  models.JsUserAuth            "Login successful - session cookie set"
// @Failure      400      {object}  map[string]string            "Bad Request - Invalid request body or expired ceremony"
// @Failure      401      {object}  map[string]string            "Unauthorized - Challenge mismatch, invalid signature, or unknown credential"
// @Failure      503      {object}  map[string]string            "Service Unavailable - Passkey support not configured"
// @Router       /auth/passkey/login/finish [post]
func (ac *AuthController) PostPasskeyLoginFinish(c *gin.Context) {
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	log.Printf("passkey: finish login session_key=%s cred_id=%s", req.SessionKey, req.Credential.ID)
	if req.SessionKey == "" {
		utils.SetGinError(c, http.StatusBadRequest, errors.New("session_key is required"))
		return
	}
	if err := validateCeremonyCredential(req.Credential); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}
	if err := withRequestBodyJSON(c, req.Credential); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("rebuild request body: %w", err))
		return
	}
	sessionData, err := ac.takeCeremony(req.SessionKey)
	if err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}
	var matched *auth.WebAuthnUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		wu, err := auth.WebAuthnUserResolver(c.Request.Context(), ac.authService)(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		resolved, ok := wu.(*auth.WebAuthnUser)
		if !ok {
			return wu, nil
		}
		matched = resolved
		return resolved, nil
	}
	_, cred, err := ac.webauthn.FinishPasskeyLogin(handler, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("login failed: %v", err)})
		return
	}
	if matched == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "could not resolve passkey owner"})
		return
	}
	rec := matched.FindCredential(cred.ID)
	if rec == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "matched passkey not in user's credential list"})
		return
	}
	if _, err := ac.authService.UpdatePasskeyCounter(c.Request.Context(), &proto.UpdatePasskeyCounterRequest{
		PasskeyId:   rec.PasskeyID,
		RequesterId: matched.UserAuth.GetId(),
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("update counter: %w", err))
		return
	}
	ac.loginUser(c, matched.UserAuth)
}

// PostLinkPasskeyBegin godoc
// @Summary      Begin linking a passkey to the authenticated account
// @Description  Starts a WebAuthn registration ceremony for the currently
// @Description  authenticated user. The challenge is keyed against the
// @Description  user's session so it cannot be replayed against a
// @Description  different account.
// @Description
// @Description  The server returns ceremony options
// @Description  (`PublicKeyCredentialCreationOptions`) that the browser
// @Description  uses to invoke the platform authenticator. The reply also
// @Description  carries the server-supplied `user_id` (base64url of the
// @Description  user's stable DB id, matching the encoding inside
// @Description  `options.user.id`) and `user_name` so the frontend does not
// @Description  have to read those values from a client-side cache.
// @Description
// @Description  Returns 503 if passkey support is not configured.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  PasskeyCeremonyBeginReply  "WebAuthn registration options"
// @Failure      401  {object}  map[string]string          "Unauthorized - User is not authenticated via session"
// @Failure      503  {object}  map[string]string          "Service Unavailable - Passkey support not configured"
// @Router       /auth/link/passkey/begin [post]
func (ac *AuthController) PostLinkPasskeyBegin(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	log.Printf("passkey: begin link userID=%q", user.ID)
	wu, err := auth.LoadPasskeyUser(c.Request.Context(), ac.authService, user.ID)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("load user: %w", err))
		return
	}
	// Exclude the user's existing credentials so the picker hides them.
	creds := webauthn.Credentials(wu.WebAuthnCredentials())
	options, sessionData, err := ac.webauthn.BeginRegistration(wu,
		webauthn.WithExclusions(creds.CredentialDescriptors()),
	)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("begin registration: %w", err))
		return
	}
	key, err := ac.putCeremony(*sessionData)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("store ceremony: %w", err))
		return
	}
	// Empty UserID/UserName on register/login endpoints; populated
	// here so the frontend need not read options.user from a
	// client cache.
	c.JSON(http.StatusOK, withLinkUser(beginReplyFrom(key, options.Response), user.ID, wu.WebAuthnName()))
}

// PostLinkPasskeyFinish godoc
// @Summary      Finish linking a passkey to the authenticated account
// @Description  Completes a WebAuthn registration ceremony started by
// @Description  `/auth/link/passkey/begin`, attaching the verified passkey
// @Description  to the currently authenticated user via
// @Description  `AuthService.RegisterPasskey`.
// @Description
// @Description  The browser posts the attestation response
// @Description  (`credential_id`, `client_data_json`, `authenticator_data`,
// @Description  `signature`) and the `session_key` from the matching /begin.
// @Description  The server verifies the challenge, origin, RP ID, and
// @Description  attestation signature, then persists the credential via
// @Description  `AuthService.RegisterPasskey` with the authenticated user
// @Description  as both `user_id` and `requester_id`.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      PasskeyCeremonyFinishRequest  true  "WebAuthn attestation response"
// @Success      200      {object}  PasskeyCeremonyFinishReply   "Passkey linked to account"
// @Failure      400      {object}  map[string]string            "Bad Request - Invalid request body or malformed attestation"
// @Failure      401      {object}  map[string]string            "Unauthorized - User is not authenticated, or challenge mismatch"
// @Failure      503      {object}  map[string]string            "Service Unavailable - Passkey support not configured"
// @Router       /auth/link/passkey/finish [post]
func (ac *AuthController) PostLinkPasskeyFinish(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if !ac.webauthnConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey support is not configured (WEBAUTHN_RP_ID unset)"})
		return
	}
	var req PasskeyCeremonyFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	log.Printf("passkey: finish link session_key=%s userID=%q cred_id=%s", req.SessionKey, user.ID, req.Credential.ID)
	if req.SessionKey == "" {
		utils.SetGinError(c, http.StatusBadRequest, errors.New("session_key is required"))
		return
	}
	if err := validateCeremonyCredential(req.Credential); err != nil {
		utils.SetGinError(c, http.StatusBadRequest, err)
		return
	}
	if err := withRequestBodyJSON(c, req.Credential); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("rebuild request body: %w", err))
		return
	}
	sessionData, cerErr := ac.takeCeremony(req.SessionKey)
	if cerErr != nil {
		utils.SetGinError(c, http.StatusBadRequest, cerErr)
		return
	}
	wu, err := auth.LoadPasskeyUser(c.Request.Context(), ac.authService, user.ID)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("load user: %w", err))
		return
	}
	cred, err := ac.webauthn.FinishRegistration(wu, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("registration failed: %v", err)})
		return
	}
	if _, err := ac.authService.RegisterPasskey(c.Request.Context(), &proto.RegisterPasskeyRequest{
		UserId:         user.ID,
		RequesterId:    user.ID,
		CredentialId:   cred.ID,
		PublicKey:      cred.PublicKey,
		Transports:     authTransports(cred.Transport),
		Aaguid:         cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		UserVerified:   cred.Flags.UserVerified,
		FriendlyName:   req.FriendlyName,
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("register passkey: %w", err))
		return
	}
	c.JSON(http.StatusOK, PasskeyCeremonyFinishReply{
		CredentialId: base64.RawURLEncoding.EncodeToString(cred.ID),
	})
}
