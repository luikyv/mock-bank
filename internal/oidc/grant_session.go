package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
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
		ID:           gs.ID,
		TokenID:      gs.TokenID,
		RefreshToken: gs.RefreshToken,
		AuthCode:     gs.AuthCode,
		ExpiresAt:    timeutil.ParseTimestamp(gs.ExpiresAtTimestamp),
		Data:         *gs,
		UpdatedAt:    timeutil.DateTimeNow(),
		OrgID:        gs.AdditionalTokenClaims[OrgIDKey].(string),
	}
	return m.db.WithContext(ctx).Save(grant).Error
}

func (m GrantSessionManager) SessionByTokenID(ctx context.Context, id string) (*goidc.GrantSession, error) {
	return m.grant(ctx, m.db.Where("token_id = ?", id))
}

func (m GrantSessionManager) SessionByRefreshToken(ctx context.Context, token string) (*goidc.GrantSession, error) {
	return m.grant(ctx, m.db.Where("refresh_token = ?", token))
}

func (m GrantSessionManager) Delete(ctx context.Context, id string) error {
	return m.db.WithContext(ctx).Where("id = ?", id).Delete(&Grant{}).Error
}

func (m GrantSessionManager) DeleteByAuthCode(ctx context.Context, code string) error {
	return m.db.WithContext(ctx).Where("auth_code = ?", code).Delete(&Grant{}).Error
}

func (m GrantSessionManager) grant(ctx context.Context, tx *gorm.DB) (*goidc.GrantSession, error) {
	var grant Grant
	if err := tx.WithContext(ctx).First(&grant).Error; err != nil {
		return nil, err
	}
	return &grant.Data, nil
}

type Grant struct {
	ID           string `gorm:"primaryKey"`
	TokenID      string
	RefreshToken string
	AuthCode     string
	ExpiresAt    timeutil.DateTime
	Data         goidc.GrantSession `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Grant) TableName() string {
	return "oauth_grants"
}
