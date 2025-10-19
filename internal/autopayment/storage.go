package autopayment

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type Storage interface {
	createConsent(ctx context.Context, consent *Consent) error
	consent(ctx context.Context, id, orgID string) (*Consent, error)
	updateConsent(ctx context.Context, c *Consent) error
	create(ctx context.Context, p *Payment) error
	payment(ctx context.Context, query Query, orgID string) (*Payment, error)
	payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error)
	update(ctx context.Context, p *Payment) error
}

type storage struct {
	db *gorm.DB
}

func (s storage) createConsent(ctx context.Context, consent *Consent) error {
	if err := s.db.WithContext(ctx).Create(consent).Error; err != nil {
		return fmt.Errorf("could not create consent: %w", err)
	}
	return nil
}

func (s storage) consent(ctx context.Context, id, orgID string) (*Consent, error) {
	c := &Consent{}
	if err := s.db.WithContext(ctx).Preload("DebtorAccount").First(c, "id = ? AND org_id = ?", id, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func (s storage) updateConsent(ctx context.Context, c *Consent) error {
	err := s.db.WithContext(ctx).
		Model(&Consent{}).
		Select("*").
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", c.ID, c.OrgID).
		Updates(c).Error
	if err != nil {
		return fmt.Errorf("could not update consent: %w", err)
	}

	return nil
}

func (s storage) create(ctx context.Context, p *Payment) error {
	if err := s.db.WithContext(ctx).Create(p).Error; err != nil {
		return fmt.Errorf("could not create payment: %w", err)
	}
	return nil
}

func (s storage) payment(ctx context.Context, query Query, orgID string) (*Payment, error) {
	dbQuery := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", query.ID)
	}
	if query.ConsentID != "" {
		dbQuery = dbQuery.Where("consent_id = ?", query.ConsentID)
	}
	if query.Statuses != nil {
		dbQuery = dbQuery.Where("status IN ?", query.Statuses)
	}
	if query.DebtorAccount {
		dbQuery = dbQuery.Preload("DebtorAccount")
	}
	if query.Order != "" {
		dbQuery = dbQuery.Order(query.Order)
	}
	p := &Payment{}
	if err := dbQuery.First(p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return p, nil
}

func (s storage) payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error) {
	if opts == nil {
		opts = &Filter{}
	}
	query := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if opts.ConsentID != "" {
		query = query.Where("consent_id = ?", strings.TrimPrefix(opts.ConsentID, ConsentURNPrefix))
	}
	if opts.Statuses != nil {
		query = query.Where("status IN ?", opts.Statuses)
	}
	if opts.From != nil {
		query = query.Where("date >= ?", opts.From)
	}
	if opts.To != nil {
		query = query.Where("date <= ?", opts.To)
	}

	var payments []*Payment
	if err := query.Find(&payments).Error; err != nil {
		return nil, fmt.Errorf("could not find payments: %w", err)
	}

	return payments, nil
}

func (s storage) update(ctx context.Context, p *Payment) error {
	err := s.db.WithContext(ctx).
		Model(&Payment{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", p.ID, p.OrgID).
		Updates(p).Error
	if err != nil {
		return fmt.Errorf("could not update payment status: %w", err)
	}

	return nil
}
