package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Avatar providers. Each provider has a `Build<Provider>Avatar`
// function that takes the provider-specific inputs and returns
// either a non-empty URL or an empty string when no avatar is
// available. The URL is what the strategy stores in UserAuth.
//
// The flow for a user with multiple linked providers is:
//   1. The frontend asks for the current UserAuth.
//   2. The REST controller returns the avatar_url from the proto.
//   3. The frontend falls back to its own InitialsAvatar if the
//      URL is null.
//
// The provider order in `PickAvatar` is the priority order: Discord
// beats Google which beats Gravatar which beats nothing.

// DiscordAvatarURL returns the avatar URL for a Discord user.
// Discord avatars are at `cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.{ext}`.
// The `avatar_hash` field is the hash returned by Discord; users
// without a custom avatar have an empty string (use the default
// Discord identicon).
func DiscordAvatarURL(discordID int64, avatarHash string) string {
	if avatarHash == "" {
		// No custom avatar. Returning the empty string lets the
		// caller fall through to the next provider or to "null"
		// on the frontend.
		return ""
	}
	// Discord returns the ext as part of the hash (e.g. "abc123.png"
	// or just "abc123" for animated gifs). The default ext is png.
	ext := "png"
	if strings.HasSuffix(avatarHash, "_a.gif") || strings.HasSuffix(avatarHash, ".gif") {
		ext = "gif"
	}
	return "https://cdn.discordapp.com/avatars/" + i64toa(discordID) + "/" + avatarHash + "." + ext
}

// GoogleAvatarURL returns the Google profile picture URL.
// Google returns a `picture` field on the OpenID userinfo endpoint;
// if the user hasn't set one, this is empty.
func GoogleAvatarURL(picture string) string {
	return picture
}

// GravatarURL returns the Gravatar URL for an email address.
// Gravatar URLs are stable per email (md5 of the lowercased,
// trimmed email). The default avatar is a colored identicon.
func GravatarURL(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(email))
	// Returning the SHA256 hex form; Gravatar accepts both md5 and
	// sha256. SHA256 is the modern recommendation.
	return "https://www.gravatar.com/avatar/" + hex.EncodeToString(sum[:]) + "?d=identicon"
}

// PickAvatar returns the first non-empty avatar URL from the
// providers, in priority order. The intent is that the REST
// controller picks the best available avatar *at auth time* so
// the frontend can render it without a follow-up call.
//
// Adding a new provider (e.g. GitHub) is a one-line change here.
func PickAvatar(urls ...string) string {
	for _, u := range urls {
		if u != "" {
			return u
		}
	}
	return ""
}

// i64toa is a tiny stdlib-free integer-to-string conversion.
// Keeping dependencies small is nice in this file because it's
// imported by every strategy.
func i64toa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
