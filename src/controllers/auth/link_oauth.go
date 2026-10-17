package auth

// Popup-based account linking.
//
// `GET /api/auth/link/:p/init` opens an OAuth dance in a popup so the
// SPA can drive a Discord / Google link without leaving the Settings
// page. The init endpoint generates a CSRF state, stores it in the
// session, and 302s to the provider. The callback endpoint verifies
// the state, exchanges the code, and calls `LinkCredential` on the
// *currently authenticated* user (instead of the login strategy which
// creates users). It then 302s to `/api/auth/link/:p/complete?payload=…`
// which serves a tiny HTML page that posts the payload to `window.opener`.
//
// The session cookie is shared between the popup and the main window
// (SameSite=Lax allows top-level navigations to send it), so the
// session doubles as the auth token AND the CSRF store. The state keys
// (`link_state_discord`, `link_state_google`) are namespaced to avoid
// colliding with the regular login flow's `state` / `google_state`.
//
// If the popup is lost (closed by user, blocked by browser), the SPA
// falls back to `POST /api/auth/link/<p>?<provider>_id=…` which is
// unchanged.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/KuramaSyu/WerSu-Rest/src/auth"
	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/models"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// linkStateKey returns the session key used to store the OAuth state
// for a link flow. Provider-scoped so simultaneous flows on different
// providers don't collide.
func linkStateKey(p string) string { return "link_state_" + p }

// linkOAuthFor returns the OAuth config and credential kind for a
// link flow. ok=false means the provider is unknown OR the link OAuth
// is not configured for that provider; callers map false -> 503.
func (ac *AuthController) linkOAuthFor(p string) (*oauth2.Config, proto.CredentialKind, bool) {
	switch p {
	case "discord":
		if ac.OAuthLinkConfig == nil {
			return nil, 0, false
		}
		return ac.OAuthLinkConfig, proto.CredentialKind_CREDENTIAL_KIND_DISCORD, true
	case "google":
		if ac.GoogleLinkOAuth == nil {
			return nil, 0, false
		}
		return ac.GoogleLinkOAuth, proto.CredentialKind_CREDENTIAL_KIND_GOOGLE, true
	}
	return nil, 0, false
}

// encodeLinkPayload serializes a payload map to a URL-safe base64
// string. The complete endpoint embeds it in `?payload=…` and the
// HTML page decodes it before posting to the SPA.
func encodeLinkPayload(payload map[string]any) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// decodeLinkPayload parses the `payload` query parameter. ok=false
// means the payload is missing or malformed.
func decodeLinkPayload(s string) (map[string]any, bool) {
	if s == "" {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false
	}
	return out, true
}

// frontendOrigin extracts the origin (scheme://host[:port]) from
// FrontendURL. Falls back to the raw value when the URL doesn't
// parse cleanly; the popup HTML page only uses it for postMessage
// targetOrigin so an empty/malformed value becomes a literal "*"
// after the parse fails.
func frontendOrigin(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// linkCompleteHTMLTmpl is the tiny HTML page that the popup serves after
// a link callback completes. It decodes the `payload` query string
// and posts it to `window.opener` so the SPA can react (close the
// popup, refresh the linked-credentials list, show a toast).
//
// When `window.opener` is missing (popup opened in a new tab, parent
// navigated, popup blocker closed the parent), the payload is
// rendered into the body so the user can copy the result manually.
// The SPA's fallback flow (`POST /api/auth/link/<p>`) handles the
// common "opener closed" case.
const linkCompleteHTMLTmpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Link complete</title>
<style>body{font-family:system-ui,sans-serif;padding:1.5rem;color:#222}</style>
</head>
<body>
<p>You can close this window.</p>
<pre id="payload" style="white-space:pre-wrap;word-break:break-all"></pre>
<script>
(function() {
  var params = new URLSearchParams(window.location.search);
  var raw = params.get('payload') || '';
  var data;
  try { data = JSON.parse(atob(raw)); }
  catch (err) {
    document.getElementById('payload').textContent = 'bad payload: ' + err.message;
    return;
  }
  document.getElementById('payload').textContent = JSON.stringify(data, null, 2);
  data.type = 'auth-link-complete';
  if (window.opener) {
    try {
      window.opener.postMessage(data, %q);
      window.close();
    } catch (err) {
      document.body.insertAdjacentHTML('afterbegin',
        '<p>postMessage failed: ' + err.message + '</p>');
    }
  }
})();
</script>
</body>
</html>
`

// GetLinkInit godoc
// @Summary      Start an OAuth link flow in a popup
// @Description  Browser-driven entry point for the OAuth account-linking
// @Description  flow used by the SPA's Security page. The SPA opens a
// @Description  popup to `GET /api/auth/link/{provider}/init`, which:
// @Description  1. Requires an active session cookie (the popup and the
// @Description     main window share the same session).
// @Description  2. Generates a CSRF `state` and stores it under the
// @Description     provider-scoped session key, bound to the current
// @Description     user id so the matching /callback cannot link into
// @Description     a different account.
// @Description  3. 302-redirects the popup to the provider's authorize
// @Description     URL with that `state` as the `state` query parameter.
// @Description
// @Description  Returns 503 when the link OAuth is not configured for
// @Description  the provider (operator did not set the matching
// @Description  `*_LINK_REDIRECT_URI` env var). When the SPA sees 503
// @Description  it falls back to the non-popup route:
// @Description  `POST /api/auth/link/discord` or
// @Description  `POST /api/auth/link/google` (literal paths, not
// @Description  templated).
// @Tags         Authentication
// @Produce      json
// @Security     CookieAuth
// @Param        p  path  string  true  "Provider: discord or google"
// @Success      307  "Redirect to provider authorize URL"
// @Failure      401  {object}  map[string]string  "Unauthorized - no session"
// @Failure      503  {object}  map[string]string  "Service Unavailable - link OAuth not configured for this provider"
// @Router       /auth/link/{p}/init [get]
func (ac *AuthController) GetLinkInit(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if user == nil {
		utils.SetGinError(c, code, err)
		return
	}
	p := c.Param("p")
	cfg, _, ok := ac.linkOAuthFor(p)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": fmt.Sprintf("OAuth linking for %q is not configured", p),
		})
		return
	}

	state, err := ac.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}
	session := sessions.Default(c)
	session.Set(linkStateKey(p), state)
	// Bind the state to the current user so a callback from a
	// different session can't link into this user's account.
	session.Set(linkStateKey(p)+"_user", user.ID)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, cfg.AuthCodeURL(state))
}

// GetLinkCallback godoc
// @Summary      OAuth link callback (server-side)
// @Description  Server-side endpoint the OAuth provider redirects to
// @Description  after the user finishes the popup-based link flow.
// @Description  This endpoint never returns JSON; it only:
// @Description  1. Verifies the CSRF `state` against the one stored in
// @Description     the session during /init, and confirms the session
// @Description     user still matches the user bound to that state.
// @Description  2. Exchanges the `code` against the provider's token
// @Description     endpoint.
// @Description  3. Fetches the provider's userinfo and calls
// @Description     `AuthService.LinkCredential` against the currently
// @Description     authenticated user (no new user is ever created).
// @Description  4. If the provider returned an avatar URL, refreshes
// @Description     the user's `avatar_url`.
// @Description  5. 302-redirects the popup to
// @Description     `/api/auth/link/{provider}/complete?payload=…`,
// @Description     where the payload is a base64url-encoded JSON
// @Description     object the SPA's main window receives via
// @Description     `postMessage`.
// @Description
// @Description  On any error in steps 1-4 the response is still a 307
// @Description  to /complete with an error payload (so the SPA can
// @Description  surface a toast instead of staring at a closed popup),
// @Description  EXCEPT for: missing `code` or state mismatch (400),
// @Description  no session (401), or link OAuth not configured (503).
// @Description
// @Description  Note: `LinkCredential` returns ALREADY_EXISTS when the
// @Description  provider id is already linked to a different user
// @Description  account. The callback surfaces this as an error
// @Description  payload on /complete; the SPA should refresh its
// @Description  linked-credentials list and show the failure.
// @Tags         Authentication
// @Produce      json
// @Security     CookieAuth
// @Param        p      path   string  true   "Provider: discord or google"
// @Param        code   query  string  true   "Authorization code returned by the provider"
// @Param        state  query  string  true   "CSRF state echoed from /init"
// @Success      307  "Redirect to /complete?payload=… (success or error payload)"
// @Failure      400  {object}  map[string]string  "Bad Request - missing code, state mismatch, or state bound to a different user"
// @Failure      401  {object}  map[string]string  "Unauthorized - no session"
// @Failure      500  {object}  map[string]string  "Internal Server Error - code exchange / userinfo failure when /complete cannot be reached"
// @Failure      503  {object}  map[string]string  "Service Unavailable - link OAuth not configured for this provider"
// @Router       /auth/link/{p}/callback [get]
func (ac *AuthController) GetLinkCallback(c *gin.Context) {
	user, code, err := utils.UserFromContext(c)
	if user == nil {
		utils.SetGinError(c, code, err)
		return
	}
	p := c.Param("p")
	cfg, kind, ok := ac.linkOAuthFor(p)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": fmt.Sprintf("OAuth linking for %q is not configured", p),
		})
		return
	}

	session := sessions.Default(c)
	savedState, _ := session.Get(linkStateKey(p)).(string)
	if savedState == "" || savedState != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}
	savedUser, _ := session.Get(linkStateKey(p) + "_user").(string)
	session.Delete(linkStateKey(p))
	session.Delete(linkStateKey(p) + "_user")
	_ = session.Save()
	if savedUser != "" && savedUser != user.ID {
		// The state was minted for a different session user.
		// Reject so a flow started by user A can't link into B.
		c.JSON(http.StatusBadRequest, gin.H{"error": "state does not match session user"})
		return
	}

	codeStr := c.Query("code")
	if codeStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
		return
	}

	token, err := cfg.Exchange(c, codeStr)
	if err != nil {
		utils.SetGinError(c, http.StatusInternalServerError,
			fmt.Errorf("%s code exchange failed: %w", p, err))
		return
	}

	// Build the postMessage payload. Errors during the link dance
	// still serve the complete page so the SPA can react to a
	// failure instead of staring at a closed popup.
	payload, linkErr := ac.linkFromOAuth(c, p, kind, cfg, token, user.ID)
	if linkErr != nil {
		log.Printf("link %s: %v", p, linkErr)
		payload = map[string]any{
			"provider": p,
			"error":    linkErr.Error(),
		}
	}
	encoded, err := encodeLinkPayload(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode payload"})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, "/api/auth/link/"+p+"/complete?payload="+encoded)
}

// linkFromOAuth runs the provider-specific part of the link callback:
// fetches the provider profile, calls LinkCredential against the
// currently authenticated user, optionally refreshes the avatar,
// and returns the postMessage payload.
//
// Errors are returned with enough context for the caller to log them;
// the payload sent to the SPA on success contains `provider`, `id`,
// `username`, and (for Discord) `avatar` / (for Google) `picture`.
func (ac *AuthController) linkFromOAuth(
	c *gin.Context,
	p string,
	kind proto.CredentialKind,
	cfg *oauth2.Config,
	token *oauth2.Token,
	userID string,
) (map[string]any, error) {
	switch kind {
	case proto.CredentialKind_CREDENTIAL_KIND_DISCORD:
		client := cfg.Client(c, token)
		userinfoURL := ac.DiscordUserinfoURL
		if userinfoURL == "" {
			userinfoURL = "https://discord.com/api/users/@me"
		}
		resp, err := client.Get(userinfoURL)
		if err != nil {
			return nil, fmt.Errorf("discord userinfo fetch failed: %w", err)
		}
		defer resp.Body.Close()
		var d models.DiscordUser
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			return nil, fmt.Errorf("discord userinfo parse: %w", err)
		}
		did := fmt.Sprintf("%d", int64(d.DiscordId))
		if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
			UserId:      userID,
			RequesterId: userID,
			Kind:        proto.CredentialKind_CREDENTIAL_KIND_DISCORD,
			Payload:     &proto.LinkCredentialRequest_DiscordId{DiscordId: did},
		}); err != nil {
			return nil, fmt.Errorf("link discord failed: %w", err)
		}
		if avatarURL := auth.DiscordAvatarURL(int64(d.DiscordId), d.Avatar); avatarURL != "" {
			if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
				UserId:      userID,
				RequesterId: userID,
				AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
					AvatarUrlSet: avatarURL,
				},
			}); err != nil {
				// Non-fatal: the credential is linked, but the
				// avatar didn't update. The SPA will see the old
				// avatar until the next refresh.
				log.Printf("link discord: avatar update failed: %v", err)
			}
		}
		return map[string]any{
			"provider": "discord",
			"id":       did,
			"username": d.Username,
			"avatar":   d.Avatar,
		}, nil

	case proto.CredentialKind_CREDENTIAL_KIND_GOOGLE:
		client := cfg.Client(c, token)
		userinfoURL := ac.GoogleUserinfoURL
		if userinfoURL == "" {
			userinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		}
		resp, err := client.Get(userinfoURL)
		if err != nil {
			return nil, fmt.Errorf("google userinfo fetch failed: %w", err)
		}
		defer resp.Body.Close()
		var gu struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			Picture       string `json:"picture"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&gu); err != nil {
			return nil, fmt.Errorf("google userinfo parse: %w", err)
		}
		if gu.Sub == "" {
			return nil, fmt.Errorf("google userinfo returned empty sub")
		}
		if _, err := ac.authService.LinkCredential(c, &proto.LinkCredentialRequest{
			UserId:      userID,
			RequesterId: userID,
			Kind:        proto.CredentialKind_CREDENTIAL_KIND_GOOGLE,
			Payload:     &proto.LinkCredentialRequest_GoogleId{GoogleId: gu.Sub},
		}); err != nil {
			return nil, fmt.Errorf("link google failed: %w", err)
		}
		if avatarURL := auth.GoogleAvatarURL(gu.Picture); avatarURL != "" {
			if _, err := ac.authService.UpdateUserAuth(c, &proto.UpdateUserAuthRequest{
				UserId:      userID,
				RequesterId: userID,
				AvatarUrlChange: &proto.UpdateUserAuthRequest_AvatarUrlSet{
					AvatarUrlSet: avatarURL,
				},
			}); err != nil {
				log.Printf("link google: avatar update failed: %v", err)
			}
		}
		return map[string]any{
			"provider": "google",
			"id":       gu.Sub,
			"email":    gu.Email,
			"username": gu.Name,
			"picture":  gu.Picture,
		}, nil
	}
	return nil, fmt.Errorf("unsupported link provider %q", p)
}

// GetLinkComplete godoc
// @Summary      Serve the link-complete HTML page
// @Description  Serves a tiny self-contained HTML page that the popup
// @Description  loads after `/api/auth/link/{provider}/callback`
// @Description  302-redirects into it. The page:
// @Description  1. Decodes the `payload` query parameter (a
// @Description     base64url-encoded JSON object, see the payload
// @Description     schema below).
// @Description  2. Calls `window.opener.postMessage(payload,
// @Description     FRONTEND_URL_ORIGIN)` so the SPA's main window can
// @Description     react (close the popup, refresh linked credentials,
// @Description     show a toast).
// @Description  3. Calls `window.close()`.
// @Description
// @Description  If `window.opener` is missing (popup opened in a new
// @Description  tab, parent navigated away, popup blocker closed the
// parent), the payload is rendered into the visible `<pre>` element so
// the user can copy it manually. The SPA should treat a missing
// postMessage as a fallback trigger and re-run the link via
// @Description  `POST /api/auth/link/{provider}` (literal path).
// @Description
// @Description  Payload schema (JSON object):
// @Description  - `provider` (string): "discord" or "google".
// @Description  - `id` (string): Discord snowflake or Google `sub`.
// @Description  - `username` (string): provider-side display name.
// @Description  - `avatar` (string, Discord only): Discord avatar hash.
// @Description  - `picture` (string, Google only): Google picture URL.
// @Description  - `email` (string, Google only): email from userinfo.
// @Description  - `error` (string): present iff linking errored; the
// @Description    rest of the fields are omitted.
// @Tags         Authentication
// @Produce      html
// @Param        p        path   string  true   "Provider: discord or google"
// @Param        payload  query  string  true   "Base64url-encoded JSON payload produced by /callback"
// @Success      200  "HTML page that postMessages the payload to window.opener"
// @Failure      400  {object}  map[string]string  "Bad Request - payload missing or not valid base64url JSON"
// @Failure      404  {object}  map[string]string  "Not Found - unknown provider"
// @Router       /auth/link/{p}/complete [get]
func (ac *AuthController) GetLinkComplete(c *gin.Context) {
	p := c.Param("p")
	if p != "discord" && p != "google" {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("unknown provider %q", p)})
		return
	}
	if _, ok := decodeLinkPayload(c.Query("payload")); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing or malformed payload"})
		return
	}
	origin := frontendOrigin(config.AppConfig.FrontendURL)
	html := fmt.Sprintf(linkCompleteHTMLTmpl, origin)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_, _ = c.Writer.WriteString(html)
}
