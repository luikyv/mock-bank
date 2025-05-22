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

type GrantSessionManager struct {
	db *gorm.DB
}

func NewGrantSessionManager(db *gorm.DB) GrantSessionManager {
	return GrantSessionManager{db: db}
}

func (m GrantSessionManager) Save(ctx context.Context, gs *goidc.GrantSession) error {
	grant := &Grant{
		ID:             gs.ID,
		TokenID:        gs.TokenID,
		RefreshTokenID: gs.RefreshTokenID,
		AuthCode:       gs.AuthCode,
		ExpiresAt:      parseTimestamp(gs.ExpiresAtTimestamp),
		Data:           marshalJSON(gs),
		UpdatedAt:      timeutil.Now(),
		OrgID:          gs.AdditionalTokenClaims["org_id"].(string),
	}
	return m.db.WithContext(ctx).Save(grant).Error
}

func (m GrantSessionManager) SessionByTokenID(ctx context.Context, id string) (*goidc.GrantSession, error) {
	return m.grant(ctx, m.db.Where("token_id = ?", id))
}

func (m GrantSessionManager) SessionByRefreshTokenID(ctx context.Context, id string) (*goidc.GrantSession, error) {
	return m.grant(ctx, m.db.Where("refresh_token_id = ?", id))
}

func (m GrantSessionManager) Delete(ctx context.Context, id string) error {
	return m.db.WithContext(ctx).Where("id = ?", id).Delete(&Client{}).Error
}

func (m GrantSessionManager) DeleteByAuthCode(ctx context.Context, code string) error {
	return m.db.WithContext(ctx).Where("auth_code = ?", code).Delete(&Client{}).Error
}

func (m GrantSessionManager) grant(ctx context.Context, tx *gorm.DB) (*goidc.GrantSession, error) {

	var grant Grant
	if err := tx.WithContext(ctx).First(&grant).Error; err != nil {
		return nil, err
	}

	var oidcGrant goidc.GrantSession
	if err := unmarshalJSON(grant.Data, &oidcGrant); err != nil {
		return nil, fmt.Errorf("could not load the grant session: %w", err)
	}
	return &oidcGrant, nil
}

type Grant struct {
	ID             string `gorm:"primaryKey"`
	TokenID        string
	RefreshTokenID string
	AuthCode       string
	ExpiresAt      time.Time
	Data           datatypes.JSON

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Grant) TableName() string {
	return "oauth_grants"
}
