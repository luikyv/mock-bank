package creditop

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	storage storage
}

func NewService(db *gorm.DB, mockOrgID string) Service {
	return Service{storage: storage{db: db, mockOrgID: mockOrgID}}
}

func (s Service) WithStorage(storage storage) Service {
	return Service{storage: storage}
}

func (s Service) Create(ctx context.Context, contract *Contract) error {
	contract.CreatedAt = timeutil.DateTimeNow()
	contract.UpdatedAt = timeutil.DateTimeNow()
	return s.storage.create(ctx, contract)
}

func (s Service) ConsentedContract(ctx context.Context, contractID, consentID, orgID string) (*Contract, error) {
	consentContract, err := s.storage.consentContract(ctx, contractID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	if consentContract.Status != resource.StatusAvailable {
		return nil, ErrNotAllowed
	}

	return consentContract.Contract, nil
}

func (s Service) Contracts(ctx context.Context, ownerID, orgID string, resourceType resource.Type, pag page.Pagination) (page.Page[*Contract], error) {
	return s.storage.contracts(ctx, ownerID, orgID, resourceType, pag)
}

func (s Service) ConsentedContracts(ctx context.Context, consentID, orgID string, resourceType resource.Type, pag page.Pagination) (page.Page[*Contract], error) {
	consentContracts, err := s.storage.consentContracts(ctx, consentID, orgID, resourceType, pag)
	if err != nil {
		return page.Page[*Contract]{}, err
	}

	var contracts []*Contract
	for _, consentContract := range consentContracts.Records {
		contracts = append(contracts, consentContract.Contract)
	}

	return page.New(contracts, pag, consentContracts.TotalRecords), nil
}

func (s Service) AuthorizeContracts(
	ctx context.Context,
	ids []string,
	consentID, ownerID, orgID string,
	resourceType resource.Type,
) error {
	return s.storage.transaction(ctx, func(txStorage storage) error {
		for _, id := range ids {
			if err := txStorage.createConsentContract(ctx, &ConsentContract{
				ConsentID:  uuid.MustParse(consentID),
				ContractID: uuid.MustParse(id),
				OwnerID:    uuid.MustParse(ownerID),
				Status:     resource.StatusAvailable,
				Type:       resourceType,
				OrgID:      orgID,
				CreatedAt:  timeutil.DateTimeNow(),
				UpdatedAt:  timeutil.DateTimeNow(),
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
	if _, err := s.ConsentedContract(ctx, contractID, consentID, orgID); err != nil {
		return page.Page[*Warranty]{}, err
	}

	return s.storage.warranties(ctx, contractID, orgID, pag)
}

func (s Service) ConsentedRealesePayments(
	ctx context.Context,
	contractID, consentID, orgID string,
	resourceType resource.Type,
	pag page.Pagination,
) (*Contract, page.Page[*ReleasePayment], error) {
	contract, err := s.ConsentedContract(ctx, contractID, consentID, orgID)
	if err != nil {
		return nil, page.Page[*ReleasePayment]{}, err
	}

	payments, err := s.storage.realesePayments(ctx, contractID, orgID, pag)
	if err != nil {
		return nil, page.Page[*ReleasePayment]{}, err
	}

	return contract, payments, nil
}

func (s Service) ConsentedBalloonPayments(
	ctx context.Context,
	contractID, consentID, orgID string,
	resourceType resource.Type,
	pag page.Pagination,
) (*Contract, page.Page[*BalloonPayment], error) {
	contract, err := s.ConsentedContract(ctx, contractID, consentID, orgID)
	if err != nil {
		return nil, page.Page[*BalloonPayment]{}, err
	}

	balloonPayments, err := s.storage.balloonPayments(ctx, contractID, orgID, pag)
	if err != nil {
		return nil, page.Page[*BalloonPayment]{}, err
	}

	return contract, balloonPayments, nil
}
