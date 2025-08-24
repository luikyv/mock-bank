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
	query := s.db.WithContext(ctx).Where("org_id = ?", orgID).Order("created_at DESC")
	if filter.OwnerID != "" {
		query = query.Where("owner_id = ?", filter.OwnerID)
	}
	if filter.ConsentID != "" {
		query = query.Where("consent_id = ?", filter.ConsentID)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}

	rs, err := page.Paginate[*Resource](query, pag)
	if err != nil {
		return page.Page[*Resource]{}, fmt.Errorf("could not find consented resources: %w", err)
	}

	return rs, nil
}
