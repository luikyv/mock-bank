package resource

import (
	"context"
	"fmt"
	"time"

	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/timeutil"
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
	if filter.OwnerID != "" {
		query = query.Where("owner_id = ?", filter.OwnerID)
	}
	if filter.ConsentID != "" {
		query = query.Where("consent_id = ?", filter.ConsentID)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
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

	for i, r := range rs {
		// Allow access to resource if it is pending authorization for more than 3 minutes.
		if r.Status == StatusPendingAuthorization && timeutil.DateTimeNow().After(r.UpdatedAt.Add(3*time.Minute)) {
			rs[i].Status = StatusAvailable
		}
	}

	return page.New(rs, pag, int(total)), nil
}
