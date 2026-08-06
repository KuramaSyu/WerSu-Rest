package models

import (
	"fmt"
	"strconv"
	"time"
)

type DiscordUser struct {
	DiscordId     Snowflake `json:"id"`
	Username      string    `json:"username"`
	Discriminator string    `json:"discriminator"`
	Avatar        string    `json:"avatar"`
	Email         string    `json:"email"`
}

// Discord User + WerSu ID Representation
type User struct {
	ID            string    `json:"id"`
	DiscordId     Snowflake `json:"discord_id"`
	Username      string    `json:"username"`
	Discriminator string    `json:"discriminator"`
	Avatar        string    `json:"avatar"`
	Email         string    `json:"email"`
}

// GetAvatarURL returns the user's Discord avatar URL
func (u *User) GetAvatarURL() string {
	return fmt.Sprintf("https://cdn.discordapp.com/avatars/%v/%v.png", u.ID, u.Avatar)
}
func (s *User) ParseJS() JsUser {

	return JsUser{
		ID:            s.ID,
		DiscordId:     fmt.Sprint(s.DiscordId),
		Username:      s.Username,
		Discriminator: s.Discriminator,
		Avatar:        s.Avatar,
		Email:         s.Email,
	}
}

type JsUser struct {
	ID            string `json:"id,omitempty"`
	DiscordId     string `json:"discord_id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
}

// Parse the return value from disccord
func (s *JsUser) Parse() (*User, error) {
	// parse the discord ID out of the JSON payload
	discordIDValue := s.DiscordId
	if discordIDValue == "" {
		discordIDValue = s.ID
	}

	discordID, err := strconv.ParseUint(discordIDValue, 10, 64)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:            s.ID,
		DiscordId:     Snowflake(discordID),
		Username:      s.Username,
		Discriminator: s.Discriminator,
		Avatar:        s.Avatar,
		Email:         s.Email,
	}, nil
}

// JsUserAuth is the JSON shape of an authenticated user from the auth
// proto's `UserAuth`. It deliberately drops the legacy Discord-shaped
// fields (avatar, discriminator, snowflake) -- those are provider
// metadata, not auth identity, and live on the discord credential row.
type JsUserAuth struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username,omitempty"`
	EmailVerifiedAt time.Time `json:"email_verified_at"`
	IsActive        bool      `json:"is_active"`
	// AvatarURL is the absolute URL to the user's avatar. Empty
	// string (the protobuf zero-value) renders as JSON null, so
	// the frontend sees `avatar_url: null` when no provider has
	// resolved an avatar.
	AvatarURL string `json:"avatar_url"`
}
