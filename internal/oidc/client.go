package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"

	"gorm.io/datatypes"
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
		Data:      marshalJSON(oidcClient),
		UpdatedAt: timeutil.Now(),
		OrgID:     oidcClient.CustomAttribute("org_id").(string),
	}
	return cm.db.WithContext(ctx).Save(client).Error
}

func (cm ClientManager) Client(ctx context.Context, id string) (*goidc.Client, error) {
	var client Client
	if err := cm.db.WithContext(ctx).First(&client, "id = ?", id).Error; err != nil {
		return nil, err
	}

	var oidcClient goidc.Client
	if err := unmarshalJSON(client.Data, &oidcClient); err != nil {
		return nil, fmt.Errorf("could not load the client: %w", err)
	}
	return &oidcClient, nil
}

func (cm ClientManager) Delete(ctx context.Context, id string) error {
	return cm.db.WithContext(ctx).Where("id = ?", id).Delete(&Client{}).Error
}

type Client struct {
	ID   string `gorm:"primaryKey"`
	Data datatypes.JSON

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Client) TableName() string {
	return "oauth_clients"
}
