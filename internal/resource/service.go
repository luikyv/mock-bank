package resource

import (
	"context"
	"fmt"

	"github.com/luikyv/mock-bank/internal/page"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{
		db: db,
	}
}

func (s Service) Resources(ctx context.Context, orgID string, filter Filter, pag page.Pagination) (page.Page[*Resource], error) {
	query := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if filter.UserID != "" {
		query = query.Where("user_id = ?", filter.UserID)
	}
	if filter.ConsentID != "" {
		query = query.Where("consent_id = ?", filter.ConsentID)
	}

	var rs []*Resource
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&rs).Error; err != nil {
		return page.Page[*Resource]{}, fmt.Errorf("could not find consented resources: %w", err)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Resource]{}, fmt.Errorf("count failed: %w", err)
	}

	return page.New(rs, pag, int(total)), nil
}
