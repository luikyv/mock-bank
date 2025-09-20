package creditportability

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

type storage struct {
	db *gorm.DB
}

func (s storage) create(ctx context.Context, portability *Portability) error {
	if err := s.db.WithContext(ctx).Create(portability).Error; err != nil {
		return fmt.Errorf("could not create portability: %w", err)
	}
	return nil
}

func (s storage) update(ctx context.Context, portability *Portability) error {
	if err := s.db.WithContext(ctx).
		Model(&Portability{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", portability.ID, portability.OrgID).
		Updates(portability).Error; err != nil {
		return fmt.Errorf("could not update portability: %w", err)
	}
	return nil
}

func (s storage) portability(ctx context.Context, query Query, orgID string) (*Portability, error) {
	dbQuery := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", query.ID)
	}
	if query.ContractID != "" {
		dbQuery = dbQuery.Where("contract_id = ?", query.ContractID)
	}
	if query.ConsentID != "" {
		dbQuery = dbQuery.Where("consent_id = ?", query.ConsentID)
	}
	if query.Statuses != nil {
		dbQuery = dbQuery.Where("status IN ?", query.Statuses)
	}
	if query.LoadContract {
		dbQuery = dbQuery.Preload("Contract")
	}

	portability := &Portability{}
	if err := dbQuery.First(portability).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return portability, nil
}

func (s storage) eligibility(ctx context.Context, contractID, orgID string) (*Eligibility, error) {
	eligibility := &Eligibility{}
	if err := s.db.WithContext(ctx).Where("contract_id = ? AND org_id = ?", contractID, orgID).First(eligibility).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return eligibility, nil
}
