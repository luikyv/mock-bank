package jwtutil

import (
	"context"
	"errors"
	"fmt"

	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{db: db}
}

func (s *Service) CheckJTI(ctx context.Context, jti, orgID string) (bool, error) {
	err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", jti, orgID).First(&JTI{}).Error
	if err == nil {
		return false, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, fmt.Errorf("failed to check jti: %w", err)
	}

	return true, s.createJTI(ctx, jti, orgID)
}

func (s *Service) createJTI(ctx context.Context, jti, orgID string) error {
	if err := s.db.WithContext(ctx).Create(&JTI{
		ID:        jti,
		OrgID:     orgID,
		UpdatedAt: timeutil.DateTimeNow(),
		CreatedAt: timeutil.DateTimeNow(),
	}).Error; err != nil {
		return fmt.Errorf("failed to create jti: %w", err)
	}

	return nil
}
