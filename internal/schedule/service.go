package schedule

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{db: db}
}

func (s Service) Schedule(ctx context.Context, schedule *Schedule) {
	schedule.UpdatedAt = timeutil.DateTimeNow()
	if err := s.db.WithContext(ctx).Omit("CreatedAt").Save(schedule).Error; err != nil {
		slog.ErrorContext(ctx, "failed to schedule task", "error", err)
	}
}

func (s Service) Unschedule(ctx context.Context, id, orgID string) {
	if err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).Delete(&Schedule{}).Error; err != nil {
		slog.ErrorContext(ctx, "failed to unschedule task", "id", id, "org_id", orgID, "error", err)
	}
}

func (s Service) Schedules(ctx context.Context, pag page.Pagination) (page.Page[*Schedule], error) {
	now := timeutil.DateTimeNow()
	query := s.db.WithContext(ctx).Model(&Schedule{}).
		// Fetch the oldest schedules first.
		Order("next_run_at ASC").
		// Fetch only schedules that are due but at most 6 hours in the past.
		Where("next_run_at < ? AND next_run_at > ?", now, now.Add(-6*time.Hour))

	schedules, err := page.Paginate[*Schedule](query, pag)
	if err != nil {
		return page.Page[*Schedule]{}, fmt.Errorf("could not find schedules: %w", err)
	}

	return schedules, nil
}
