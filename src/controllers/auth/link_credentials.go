package auth

// Non-popup credential linking and the /auth/me/credentials and
// /auth/passkey/{list,:id} management endpoints. Popup-based linking
// lives in link_oauth.go.

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PostLinkDiscord godoc
// @Summary      Link a Discord account to the authenticated user
// @Description  Attaches a Discord credential to the currently
// @Description  authenticated user via AuthService.LinkCredential.
// @Description  The frontend performs the OAuth code exchange
// @Description  itself, then POSTs the resolved `discord_id`
// @Description  (and optional `avatar_hash`) as query parameters.
// @Description  On success the user's `avatar_url` is refreshed
// @Description  from the Discord CDN when `avatar_hash` is given.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        discord_id   query     string  true   "Discord snowflake id returned from the OAuth userinfo"
// @Param        avatar_hash  query     string  false  "Discord avatar hash; when set, the avatar is refreshed"
// @Success      200  {object}  map[string]string  "linked"
// @Failure      400  {object}  map[string]string  "missing or non-integer discord_id"
// @Failure      401  {object}  map[string]string  "unauthenticated"
// @Router       /auth/link/discord [post]
func (ac *AuthController) PostLinkDiscord(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	discordId := c.Query("discord_id")
	avatarHash := c.Query("avatar_hash")
	if discordId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "discord_id is required"})
		return
	}
	did, err := strconv.ParseInt(discordId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "discord_id must be an integer"})
		return
	}
	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
		Payload:     &proto.LinkCredentialRequest_DiscordId{DiscordId: discordId},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link discord failed: %w", err))
		return
	}

	// Refresh the avatar with the new Discord provider. The
	// frontend should call this with the latest Discord profile
	// data after the OAuth dance.
	if avatarURL := auth.DiscordAvatarURL(did, avatarHash); avatarURL != "" {
		if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
			UserId:      user.ID,
			RequesterId: user.ID,
			AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
				AvatarUrlSet: avatarURL,
			},
		}); err != nil {
			// Non-fatal: the credential is linked, but the avatar
			// didn't update. The frontend will see the old avatar
			// until the next refresh.
			log.Printf("link discord: avatar update failed: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"linked": "discord"})
}

// PostLinkGoogle godoc
// @Summary      Link a Google account to the authenticated user
// @Description  Attaches a Google credential to the currently
// @Description  authenticated user via AuthService.LinkCredential.
// @Description  The frontend performs the OAuth code exchange
// @Description  itself, then POSTs the resolved `google_id`
// @Description  (and optional `picture` URL) as query parameters.
// @Description  On success the user's `avatar_url` is refreshed
// @Description  from the submitted `picture` when present.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        google_id  query     string  true   "Google stable user id from the `sub` claim"
// @Param        picture    query     string  false  "Absolute picture URL from Google userinfo; when set, the avatar is refreshed"
// @Success      200  {object}  map[string]string  "linked"
// @Failure      400  {object}  map[string]string  "missing google_id"
// @Failure      401  {object}  map[string]string  "unauthenticated"
// @Router       /auth/link/google [post]
func (ac *AuthController) PostLinkGoogle(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	googleId := c.Query("google_id")
	picture := c.Query("picture")
	if googleId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "google_id is required"})
		return
	}
	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
		Payload:     &proto.LinkCredentialRequest_GoogleId{GoogleId: googleId},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link google failed: %w", err))
		return
	}

	// Refresh the avatar with the new Google provider. The frontend
	// should call this with the latest Google userinfo data after
	// the OAuth dance.
	if avatarURL := auth.GoogleAvatarURL(picture); avatarURL != "" {
		if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
			UserId:      user.ID,
			RequesterId: user.ID,
			AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
				AvatarUrlSet: avatarURL,
			},
		}); err != nil {
			log.Printf("link google: avatar update failed: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"linked": "google"})
}

// PostChangePassword godoc
// @Summary      Change or set the authenticated user's password
// @Description  Hashes the submitted current password and compares it
// @Description  in constant time against the stored hash. On match,
// the old credential is unlinked and the new (hashed) credential is
// @Description  linked.
// @Description
// @Description  If the account has no password credential yet,
// @Description  `current_password` may be omitted and the endpoint
// @Description  acts as a first-time password setup.
// @Description
// @Description  Returns 401 on a wrong current password.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      ChangePasswordRequest  true  "current and new password"
// @Success      200      {object}  map[string]string      "password changed"
// @Failure      400      {object}  map[string]string      "missing fields or no password set"
// @Failure      401      {object}  map[string]string      "unauthenticated or wrong current password"
// @Router       /auth/password/change [post]
func (ac *AuthController) PostChangePassword(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new_password is required"})
		return
	}
	// current_password is only required when a credential already exists;
	// that branch enforces it below.
	if req.CurrentPassword == req.NewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new_password must differ from current_password"})
		return
	}

	// credentialID stays empty when no prior password credential exists;
	// we skip both the verify and the unlink in that case.
	var credentialID string
	lookup, err := ac.authService.FindCredentialByProvider(c, &proto.FindCredentialByProviderRequest{
		Kind:       proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Identifier: &proto.FindCredentialByProviderRequest_Email{Email: user.Email},
	})
	switch {
	case err == nil:
		credentialID = lookup.GetCredential().GetId()
		storedHash := lookup.GetCredential().GetPasswordHash()
		if storedHash == "" || credentialID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no password credential to update"})
			return
		}
		if req.CurrentPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "current_password is required to change an existing password"})
			return
		}
		ok, verr := auth.Argon2Hasher{}.Verify(req.CurrentPassword, storedHash)
		if verr != nil || !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid current password"})
			return
		}
	case auth.IsNotFound(err):
		// First-time password setup; fall through to LinkCredential below.
	default:
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("lookup password credential: %w", err))
		return
	}

	newHash, err := auth.Argon2Hasher{}.Hash(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Unlink the old row first when one exists. LinkCredential returns
	// ALREADY_EXISTS when a PASSWORD credential already exists, so we
	// can't just overwrite.
	if credentialID != "" {
		if _, err := ac.authService.UnlinkCredential(c, &proto.UnlinkCredentialRequest{
			CredentialId: credentialID,
			UserId:       user.ID,
			RequesterId:  user.ID,
		}); err != nil {
			utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("unlink old password credential: %w", err))
			return
		}
	}

	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload:     &proto.LinkCredentialRequest_PasswordHash{PasswordHash: newHash},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link new password credential: %w", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"changed": "password"})
}

// PostLinkPassword godoc
// @Summary      Link a password to the authenticated user
// @Description  Sets a password credential on the currently
// @Description  authenticated user. The body carries the new
// @Description  plaintext password; the server hashes it (argon2id)
// @Description  before reaching gRPC. OAuth-only signups should use
// @Description  this endpoint to add a password fallback.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      LinkPasswordRequest  true  "new plaintext password"
// @Success      200  {object}  map[string]string  "linked"
// @Failure      400  {object}  map[string]string  "missing or invalid password"
// @Failure      401  {object}  map[string]string  "unauthenticated"
// @Router       /auth/link/password [post]
func (ac *AuthController) PostLinkPassword(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req LinkPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
		return
	}
	hash, err := auth.Argon2Hasher{}.Hash(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
		UserId:      user.ID,
		RequesterId: user.ID,
		Kind:        proto.CredentialKind_CREDENTIAL_KIND_PASSWORD,
		Payload:     &proto.LinkCredentialRequest_PasswordHash{PasswordHash: hash},
	}); err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("link password failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": "password"})
}

// GetLinkedCredentials godoc
// @Summary      List my linked credentials and passkeys
// @Description  Returns every credential linked to the currently
// @Description  authenticated user (Discord, Google, password) and
// @Description  every passkey registered on their account.
// @Tags         Authentication
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  map[string]interface{}  "credentials array and passkeys array"
// @Failure      401  {object}  map[string]string        "Unauthorized - no session"
// @Failure      500  {object}  map[string]string        "Internal Server Error - gRPC service failure"
// @Router       /auth/me/credentials [get]
func (ac *AuthController) GetLinkedCredentials(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	resp, err := ac.authService.ListLinkedCredentials(c, &proto.ListLinkedCredentialsRequest{
		UserId: user.ID,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("list linked credentials failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"credentials": resp.GetCredentials(),
		"passkeys":    resp.GetPasskeys(),
	})
}

// GetPasskeysForMe godoc
// @Summary      List my passkeys
// @Description  Returns the passkeys owned by the currently authenticated
// @Description  user. Revoked rows are excluded unless `include_revoked=true`.
// @Tags         Authentication
// @Produce      json
// @Param        include_revoked  query     bool  false  "Include revoked passkeys"
// @Success      200              {object}  map[string]interface{}  "passkeys array"
// @Failure      401              {object}  map[string]string      "Unauthorized - no session"
// @Router       /auth/passkey/list [get]
func (ac *AuthController) GetPasskeysForMe(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	includeRevoked := strings.EqualFold(c.Query("include_revoked"), "true")
	resp, err := ac.authService.ListPasskeys(c.Request.Context(), &proto.ListPasskeysRequest{
		UserId:         user.ID,
		IncludeRevoked: includeRevoked,
	})
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("list passkeys failed: %w", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"passkeys": resp.GetPasskeys()})
}

// DeletePasskey godoc
// @Summary      Revoke one of my passkeys
// @Description  Revokes the passkey identified by `:id`. The actor must
// @Description  own it -- cross-user revoke attempts are rejected as 404
// @Description  so we do not leak existence of passkeys owned by other
// @Description  users. Revoke is idempotent: a row that is already revoked
// @Description  resolves to 204 No Content so a flaky network that
// @Description  double-fires still resolves cleanly.
// @Tags         Authentication
// @Param        id  path  string  true  "Passkey ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string  "Bad Request - missing id"
// @Failure      401  {object}  map[string]string  "Unauthorized - no session"
// @Failure      404  {object}  map[string]string  "Not Found - passkey not owned by caller or already revoked cross-user"
// @Router       /auth/passkey/{id} [delete]
func (ac *AuthController) DeletePasskey(c *gin.Context) {
	user, _, err := utils.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	passkeyID := strings.TrimSpace(c.Param("id"))
	if passkeyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passkey id is required"})
		return
	}
	if _, err := ac.authService.RevokePasskey(c.Request.Context(), &proto.RevokePasskeyRequest{
		PasskeyId:   passkeyID,
		UserId:      user.ID,
		RequesterId: user.ID,
	}); err != nil {
		switch status.Code(err) {
		case codes.NotFound, codes.PermissionDenied:
			// Missing OR belongs to a different user -- collapse to 404
			// so existence of other users' rows never leaks.
			c.JSON(http.StatusNotFound, gin.H{"error": "passkey not found"})
			return
		case codes.AlreadyExists:
			// Already revoked -- 204 keeps a double-fired revoke idempotent.
			c.Status(http.StatusNoContent)
			return
		}
		utils.SetGinError(c, http.StatusInternalServerError, fmt.Errorf("revoke passkey failed: %w", err))
		return
	}
	c.Status(http.StatusNoContent)
}
