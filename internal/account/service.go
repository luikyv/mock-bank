package account

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
	storage Storage
}

func NewService(db *gorm.DB, mockOrgID string) Service {
	return Service{storage: storage{db: db, mockOrgID: mockOrgID}}
}

func (s Service) Authorize(ctx context.Context, accIDs []string, consentID, orgID string) error {
	for _, accID := range accIDs {
		acc, err := s.Account(ctx, Query{ID: accID}, orgID)
		if err != nil {
			return err
		}

		status := resource.StatusAvailable
		if acc.SubType == SubTypeJointSimple {
			status = resource.StatusPendingAuthorization
		}

		if err := s.createConsent(ctx, &ConsentAccount{
			ConsentID: uuid.MustParse(consentID),
			AccountID: uuid.MustParse(accID),
			OwnerID:   acc.OwnerID,
			Status:    status,
			OrgID:     orgID,
		}); err != nil {
			return fmt.Errorf("could not create resource for account: %w", err)
		}
	}

	return nil
}

func (s Service) Create(ctx context.Context, acc *Account) error {
	now := timeutil.DateTimeNow()
	acc.CreatedAt = now
	acc.UpdatedAt = now
	return s.storage.create(ctx, acc)
}

func (s Service) Update(ctx context.Context, acc *Account) error {
	acc.UpdatedAt = timeutil.DateTimeNow()
	return s.storage.update(ctx, acc)
}

func (s Service) UpdateConsent(ctx context.Context, consentID, accountID uuid.UUID, orgID string, status resource.Status) error {
	consentAcc, err := s.storage.consentAccount(ctx, accountID.String(), consentID.String(), orgID)
	if err != nil {
		return err
	}

	consentAcc.Status = status
	consentAcc.UpdatedAt = timeutil.DateTimeNow()
	return s.storage.updateConsent(ctx, consentAcc)
}

func (s Service) Account(ctx context.Context, query Query, orgID string) (*Account, error) {
	return s.storage.account(ctx, query, orgID)
}

func (s Service) Accounts(ctx context.Context, ownerID, orgID string, pag page.Pagination) (page.Page[*Account], error) {
	return s.storage.accounts(ctx, orgID, &Filter{OwnerID: ownerID}, pag)
}

func (s Service) ConsentedAccount(ctx context.Context, accountID, consentID, orgID string) (*Account, error) {
	consentAcc, err := s.storage.consentAccount(ctx, accountID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	if consentAcc.Status == resource.StatusPendingAuthorization {
		return nil, ErrJointAccountPendingAuthorization
	}

	if consentAcc.Status != resource.StatusAvailable {
		return nil, ErrNotAllowed
	}

	return consentAcc.Account, nil
}

func (s Service) ConsentedAccounts(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*Account], error) {
	consentAccs, err := s.storage.consentAccounts(ctx, consentID, orgID, pag)
	if err != nil {
		return page.Page[*Account]{}, err
	}

	var accs []*Account
	for _, consentAcc := range consentAccs.Records {
		accs = append(accs, consentAcc.Account)
	}
	return page.New(accs, pag, consentAccs.TotalRecords), nil
}

func (s Service) Delete(ctx context.Context, id uuid.UUID, orgID string) error {
	return s.storage.delete(ctx, id.String(), orgID)
}

func (s Service) Transactions(ctx context.Context, accountID, orgID string, filter *TransactionFilter, pag page.Pagination) (page.Page[*Transaction], error) {
	return s.storage.transactions(ctx, accountID, orgID, filter, pag)
}

func (s Service) ConsentedTransactions(ctx context.Context, accountID, consentID, orgID string, filter *TransactionFilter, pag page.Pagination) (page.Page[*Transaction], error) {
	if _, err := s.ConsentedAccount(ctx, accountID, consentID, orgID); err != nil {
		return page.Page[*Transaction]{}, err
	}

	return s.Transactions(ctx, accountID, orgID, filter, pag)
}

func (s Service) createConsent(ctx context.Context, consentAcc *ConsentAccount) error {
	now := timeutil.DateTimeNow()
	consentAcc.CreatedAt = now
	consentAcc.UpdatedAt = now
	return s.storage.createConsent(ctx, consentAcc)
}
