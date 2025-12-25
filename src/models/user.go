package models

import (
	"fmt"
	"strconv"
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
	ID            int32     `json:"id"`
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
		ID:            fmt.Sprint(s.ID),
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
	// parse the discord ID out of the JSON
	discord_id, err := strconv.Atoi(s.ID)
	if err != nil {
		return nil, err
	}

	// grpc backend id unknown at this point
	id := -1

	return &User{
		ID:            int32(id),
		DiscordId:     Snowflake(discord_id),
		Username:      s.Username,
		Discriminator: s.Discriminator,
		Avatar:        s.Avatar,
		Email:         s.Email,
	}, nil
}
