package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/timeutil"

	"gorm.io/gorm"
)

type ClientManager struct {
	db *gorm.DB
}

func NewClientManager(db *gorm.DB) ClientManager {
	return ClientManager{db: db}
}

func (cm ClientManager) Save(ctx context.Context, oidcClient *goidc.Client) error {
	client := &Client{
		ID:        oidcClient.ID,
		Data:      *oidcClient,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     oidcClient.CustomAttribute(OrgIDKey).(string),
	}
	return cm.db.WithContext(ctx).Save(client).Error
}

func (cm ClientManager) Client(ctx context.Context, id string) (*goidc.Client, error) {
	var client Client
	if err := cm.db.WithContext(ctx).First(&client, "id = ?", id).Error; err != nil {
		return nil, err
	}

	return &client.Data, nil
}

func (cm ClientManager) Delete(ctx context.Context, id string) error {
	return cm.db.WithContext(ctx).Where("id = ?", id).Delete(&Client{}).Error
}

type Client struct {
	ID   string       `gorm:"primaryKey"`
	Data goidc.Client `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Client) TableName() string {
	return "oauth_clients"
}
