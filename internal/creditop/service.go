package creditop

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db        *gorm.DB
	mockOrgID string
}

func NewService(db *gorm.DB, mockOrgID string) Service {
	return Service{db: db, mockOrgID: mockOrgID}
}

func (s Service) WithTx(tx *gorm.DB) Service {
	return NewService(tx, s.mockOrgID)
}

func (s Service) Create(ctx context.Context, contract *Contract) error {
	contract.CreatedAt = timeutil.DateTimeNow()
	contract.UpdatedAt = timeutil.DateTimeNow()
	if err := s.db.WithContext(ctx).Create(contract).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return fmt.Errorf("failed to create loan: %w", err)
	}

	return nil
}

func (s Service) Contract(ctx context.Context, id, orgID string, resourceType resource.Type) (*Contract, error) {
	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("id = ? AND type = ?", id, resourceType)

	contract := &Contract{}
	if err := query.First(contract).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return contract, nil
}

func (s Service) ConsentedContract(ctx context.Context, contractID, consentID, orgID string, resourceType resource.Type) (*Contract, error) {
	consentContract := &ConsentContract{}
	if err := s.db.WithContext(ctx).
		Preload("Contract").
		Where(`contract_id = ? AND consent_id = ? AND org_id = ?`, contractID, consentID, orgID).
		First(consentContract).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotAllowed
		}
		return nil, fmt.Errorf("could not fetch consent contract: %w", err)
	}

	if consentContract.Status != resource.StatusAvailable {
		return nil, ErrNotAllowed
	}

	return consentContract.Contract, nil
}

func (s Service) Contracts(ctx context.Context, ownerID, orgID string, resourceType resource.Type, pag page.Pagination) (page.Page[*Contract], error) {
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

func (s Service) ConsentedContracts(ctx context.Context, consentID, orgID string, resourceType resource.Type, pag page.Pagination) (page.Page[*Contract], error) {
	query := s.db.WithContext(ctx).
		Model(&ConsentContract{}).
		Preload("Contract").
		Where(`consent_id = ? AND org_id = ? AND type = ? AND status = ?`, consentID, orgID, resourceType, resource.StatusAvailable).
		Order("created_at DESC")

	consentContracts, err := page.Paginate[*ConsentContract](query, pag)
	if err != nil {
		return page.Page[*Contract]{}, fmt.Errorf("failed to find consented contracts: %w", err)
	}

	var contracts []*Contract
	for _, consentContract := range consentContracts.Records {
		contracts = append(contracts, consentContract.Contract)
	}

	return page.New(contracts, pag, consentContracts.TotalRecords), nil
}

func (s Service) AuthorizeContracts(ctx context.Context, ids []string, consentID, orgID string, resourceType resource.Type) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txService := s.WithTx(tx)
		for _, id := range ids {
			// TODO: Improve this.
			contract, err := txService.Contract(ctx, id, orgID, resourceType)
			if err != nil {
				return err
			}
			if err := txService.createConsentContract(ctx, &ConsentContract{
				ConsentID:  uuid.MustParse(consentID),
				ContractID: uuid.MustParse(id),
				OwnerID:    contract.OwnerID,
				Status:     resource.StatusAvailable,
				Type:       resourceType,
				OrgID:      orgID,
			}); err != nil {
				return fmt.Errorf("could not create resource for credit contract: %w", err)
			}
		}

		return nil
	})
}

func (s Service) ConsentedWarranties(
	ctx context.Context,
	contractID, consentID, orgID string,
	resourceType resource.Type,
	pag page.Pagination,
) (page.Page[*Warranty], error) {
	if _, err := s.ConsentedContract(ctx, contractID, consentID, orgID, resourceType); err != nil {
		return page.Page[*Warranty]{}, err
	}

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

func (s Service) ConsentedRealesePayments(
	ctx context.Context,
	contractID, consentID, orgID string,
	resourceType resource.Type,
	pag page.Pagination,
) (*Contract, page.Page[*ReleasePayment], error) {
	contract, err := s.ConsentedContract(ctx, contractID, consentID, orgID, resourceType)
	if err != nil {
		return nil, page.Page[*ReleasePayment]{}, err
	}

	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("contract_id = ?", contractID).
		Order("created_at DESC")

	payments, err := page.Paginate[*ReleasePayment](query, pag)
	if err != nil {
		return nil, page.Page[*ReleasePayment]{}, fmt.Errorf("failed to find consented payments: %w", err)
	}

	return contract, payments, nil
}

func (s Service) ConsentedBalloonPayments(
	ctx context.Context,
	contractID, consentID, orgID string,
	resourceType resource.Type,
	pag page.Pagination,
) (*Contract, page.Page[*BalloonPayment], error) {
	contract, err := s.ConsentedContract(ctx, contractID, consentID, orgID, resourceType)
	if err != nil {
		return nil, page.Page[*BalloonPayment]{}, err
	}

	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("contract_id = ?", contractID).
		Order("created_at DESC")

	balloonPayments, err := page.Paginate[*BalloonPayment](query, pag)
	if err != nil {
		return nil, page.Page[*BalloonPayment]{}, fmt.Errorf("failed to find consented balloon payments: %w", err)
	}

	return contract, balloonPayments, nil
}

func (s Service) createConsentContract(ctx context.Context, consentContract *ConsentContract) error {
	consentContract.CreatedAt = timeutil.DateTimeNow()
	consentContract.UpdatedAt = timeutil.DateTimeNow()
	if err := s.db.WithContext(ctx).Create(consentContract).Error; err != nil {
		return fmt.Errorf("could not create consent contract: %w", err)
	}
	return nil
}
