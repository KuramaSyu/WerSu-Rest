package proto

import (
	"fmt"

	"github.com/KuramaSyu/WerSu-Rest/src/models"
)

func (u *User) ParseJS() *models.JsUser {
	return &models.JsUser{
		ID:            fmt.Sprintf("%v", u.Id),
		DiscordId:     fmt.Sprintf("%v", u.DiscordId),
		Username:      u.Username,
		Discriminator: u.Discriminator,
		Avatar:        u.Avatar,
		Email:         u.Email,
	}
}
