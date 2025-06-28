package client

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type Client struct {
	ID          string       `gorm:"primaryKey"`
	Data        goidc.Client `gorm:"serializer:json"`
	WebhookURIs []string     `gorm:"serializer:json"`
	Name        string
	OriginURIs  []string `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Client) TableName() string {
	return "oauth_clients"
}
