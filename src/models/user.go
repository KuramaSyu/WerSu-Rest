package models

import (
	"fmt"
	"strconv"
)

// Discord User + WerSu ID Representation
type User struct {
	ID            int64     `json:"id"`
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
	ID            string `json:"id"`
	DiscordId     string `json:"discord_id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
}

func (s *JsUser) Parse() (*User, error) {
	discord_id, err := strconv.Atoi(s.DiscordId)
	if err != nil {
		return nil, err
	}

	id, err := strconv.Atoi(s.ID)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:            int64(id),
		DiscordId:     Snowflake(discord_id),
		Username:      s.Username,
		Discriminator: s.Discriminator,
		Avatar:        s.Avatar,
		Email:         s.Email,
	}, nil
}
