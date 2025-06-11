package idempotency

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{db: db}
}

func (s Service) Response(ctx context.Context, id string) (*Record, error) {
	record := Record{}
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&record).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("error fetching the idempotency record: %w", err)
	}

	return &record, nil
}

func (s Service) Create(ctx context.Context, rec *Record) error {
	if err := s.db.WithContext(ctx).Create(rec).Error; err != nil {
		return fmt.Errorf("could not save the idempotency record: %w", err)
	}

	return nil
}
