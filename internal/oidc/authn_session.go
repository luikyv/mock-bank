package oidc

import (
	"context"
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type AuthnSessionManager struct {
	db *gorm.DB
}

func NewAuthnSessionManager(db *gorm.DB) AuthnSessionManager {
	return AuthnSessionManager{db: db}
}

func (m AuthnSessionManager) Save(ctx context.Context, as *goidc.AuthnSession) error {
	session := &Session{
		ID:              as.ID,
		CallbackID:      as.CallbackID,
		AuthCode:        as.AuthCode,
		PushedAuthReqID: as.PushedAuthReqID,
		ExpiresAt:       timeutil.ParseTimestamp(as.ExpiresAtTimestamp),
		Data:            *as,
		UpdatedAt:       timeutil.DateTimeNow(),
		OrgID:           as.StoredParameter(OrgIDKey).(string),
	}

	return m.db.WithContext(ctx).Save(session).Error
}

func (m AuthnSessionManager) SessionByCallbackID(ctx context.Context, callbackID string) (*goidc.AuthnSession, error) {
	return m.session(ctx, m.db.Where("callback_id = ?", callbackID))
}

func (m AuthnSessionManager) SessionByAuthCode(ctx context.Context, code string) (*goidc.AuthnSession, error) {
	return m.session(ctx, m.db.Where("auth_code = ?", code))
}

func (m AuthnSessionManager) SessionByPushedAuthReqID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	return m.session(ctx, m.db.Where("pushed_auth_req_id = ?", id))
}

func (m AuthnSessionManager) SessionByCIBAAuthID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	return nil, errors.ErrUnsupported
}

func (m AuthnSessionManager) Delete(ctx context.Context, id string) error {
	return m.db.WithContext(ctx).Where("id = ?", id).Delete(&Session{}).Error
}

func (m AuthnSessionManager) session(ctx context.Context, tx *gorm.DB) (*goidc.AuthnSession, error) {

	var as Session
	if err := tx.WithContext(ctx).First(&as).Error; err != nil {
		return nil, err
	}

	return &as.Data, nil
}

type Session struct {
	ID              string `gorm:"primaryKey"`
	CallbackID      string
	AuthCode        string
	PushedAuthReqID string
	ExpiresAt       timeutil.DateTime
	Data            goidc.AuthnSession `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Session) TableName() string {
	return "oauth_sessions"
}
