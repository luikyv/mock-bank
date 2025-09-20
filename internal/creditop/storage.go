package creditop

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"gorm.io/gorm"
)

type storage struct {
	db        *gorm.DB
	mockOrgID string
}

func (s storage) create(ctx context.Context, contract *Contract) error {
	err := s.db.WithContext(ctx).Create(contract).Error
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrAlreadyExists
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrAlreadyExists
	}

	return fmt.Errorf("failed to create loan: %w", err)
}

func (s storage) consentContract(ctx context.Context, contractID, consentID, orgID string) (*ConsentContract, error) {
	consentContract := &ConsentContract{}
	if err := s.db.WithContext(ctx).
		Preload("Contract").
		Where("contract_id = ? AND consent_id = ? AND org_id = ?", contractID, consentID, orgID).
		First(consentContract).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotAllowed
		}
		return nil, fmt.Errorf("could not fetch consent contract: %w", err)
	}

	return consentContract, nil
}

func (s storage) contracts(ctx context.Context, ownerID, orgID string, resourceType resource.Type, pag page.Pagination) (page.Page[*Contract], error) {
	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("owner_id = ? AND type = ?", ownerID, resourceType).
		Order("created_at DESC")

	contracts, err := page.Paginate[*Contract](query, pag)
	if err != nil {
		return page.Page[*Contract]{}, fmt.Errorf("could not find contracts: %w", err)
	}

	return contracts, nil
}

func (s storage) consentContracts(ctx context.Context, consentID, orgID string, resourceType resource.Type, pag page.Pagination) (page.Page[*ConsentContract], error) {
	query := s.db.WithContext(ctx).
		Model(&ConsentContract{}).
		Preload("Contract").
		Where(`consent_id = ? AND org_id = ? AND type = ? AND status = ?`, consentID, orgID, resourceType, resource.StatusAvailable).
		Order("created_at DESC")

	consentContracts, err := page.Paginate[*ConsentContract](query, pag)
	if err != nil {
		return page.Page[*ConsentContract]{}, fmt.Errorf("failed to find consented contracts: %w", err)
	}

	return consentContracts, nil
}

func (s storage) warranties(ctx context.Context, contractID, orgID string, pag page.Pagination) (page.Page[*Warranty], error) {
	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("contract_id = ?", contractID).
		Order("created_at DESC")

	warranties, err := page.Paginate[*Warranty](query, pag)
	if err != nil {
		return page.Page[*Warranty]{}, fmt.Errorf("failed to find consented warranties: %w", err)
	}

	return warranties, nil
}

func (s storage) realesePayments(ctx context.Context, contractID, orgID string, pag page.Pagination) (page.Page[*ReleasePayment], error) {
	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("contract_id = ?", contractID).
		Order("created_at DESC")

	payments, err := page.Paginate[*ReleasePayment](query, pag)
	if err != nil {
		return page.Page[*ReleasePayment]{}, fmt.Errorf("failed to find consented payments: %w", err)
	}

	return payments, nil
}

func (s storage) balloonPayments(ctx context.Context, contractID, orgID string, pag page.Pagination) (page.Page[*BalloonPayment], error) {

	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("contract_id = ?", contractID).
		Order("created_at DESC")

	balloonPayments, err := page.Paginate[*BalloonPayment](query, pag)
	if err != nil {
		return page.Page[*BalloonPayment]{}, fmt.Errorf("failed to find consented balloon payments: %w", err)
	}

	return balloonPayments, nil
}

func (s storage) createConsentContract(ctx context.Context, consentContract *ConsentContract) error {
	if err := s.db.WithContext(ctx).Create(consentContract).Error; err != nil {
		return fmt.Errorf("could not create consent contract: %w", err)
	}
	return nil
}

func (s storage) transaction(ctx context.Context, fn func(storage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := storage{db: tx.WithContext(ctx), mockOrgID: s.mockOrgID}
		return fn(txStorage)
	})
}
