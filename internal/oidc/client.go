package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/client"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type ClientManager struct {
	service client.Service
}

func NewClientManager(service client.Service) ClientManager {
	return ClientManager{service: service}
}

func (cm ClientManager) Save(ctx context.Context, oidcClient *goidc.Client) error {
	c := &client.Client{
		ID:        oidcClient.ID,
		Data:      *oidcClient,
		Name:      oidcClient.Name,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     oidcClient.CustomAttribute(OrgIDKey).(string),
	}
	if webhookURIs, ok := oidcClient.CustomAttribute(WebhookURIsKey).([]string); ok {
		c.WebhookURIs = webhookURIs
	}
	if originURIs, ok := oidcClient.CustomAttribute(SoftwareOriginURIsKey).([]string); ok {
		c.OriginURIs = originURIs
	}
	return cm.service.Save(ctx, c)
}

func (cm ClientManager) Client(ctx context.Context, id string) (*goidc.Client, error) {
	c, err := cm.service.Client(ctx, id)
	if err != nil {
		return nil, err
	}

	return &c.Data, nil
}

func (cm ClientManager) Delete(ctx context.Context, id string) error {
	return cm.service.Delete(ctx, id)
}
