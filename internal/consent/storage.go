package consent

import (
	"context"
	"errors"
	"fmt"

	"github.com/luikyv/mock-bank/internal/page"
	"gorm.io/gorm"
)

type Storage interface {
	create(ctx context.Context, c *Consent) error
	consent(ctx context.Context, id, orgID string) (*Consent, error)
	consents(ctx context.Context, orgID string, opts *Filter, pag page.Pagination) (page.Page[*Consent], error)
	update(ctx context.Context, c *Consent) error
	createExtension(ctx context.Context, e *Extension) error
	extensions(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*Extension], error)
}

type storage struct {
	db *gorm.DB
}

func (s storage) create(ctx context.Context, c *Consent) error {
	if err := s.db.WithContext(ctx).Create(c).Error; err != nil {
		return fmt.Errorf("could not create consent: %w", err)
	}
	return nil
}

func (s storage) consent(ctx context.Context, id, orgID string) (*Consent, error) {
	c := &Consent{}
	if err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).First(c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func (s storage) consents(ctx context.Context, orgID string, opts *Filter, pag page.Pagination) (page.Page[*Consent], error) {
	query := s.db.WithContext(ctx).Model(&Consent{}).Where("org_id = ?", orgID).Order("created_at DESC")
	if opts.OwnerID != "" {
		query = query.Where("owner_id = ?", opts.OwnerID)
	}

	consents, err := page.Paginate[*Consent](query, pag)
	if err != nil {
		return page.Page[*Consent]{}, err
	}

	return consents, nil
}

func (s storage) update(ctx context.Context, c *Consent) error {
	err := s.db.WithContext(ctx).
		Model(&Consent{}).
		Omit("CreatedAt").
		Where("id = ? AND org_id = ?", c.ID, c.OrgID).
		Updates(c).Error
	if err != nil {
		return fmt.Errorf("could not update consent: %w", err)
	}

	return nil
}

func (s storage) createExtension(ctx context.Context, e *Extension) error {
	if err := s.db.WithContext(ctx).Create(e).Error; err != nil {
		return fmt.Errorf("could not create extension: %w", err)
	}
	return nil
}

func (s storage) extensions(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*Extension], error) {
	query := s.db.WithContext(ctx).Model(&Extension{}).Where("consent_id = ? AND org_id = ?", consentID, orgID).Order("created_at DESC")
	extensions, err := page.Paginate[*Extension](query, pag)
	if err != nil {
		return page.Page[*Extension]{}, err
	}
	return extensions, nil
}
