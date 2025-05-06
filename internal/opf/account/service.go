package account

import (
	"context"
	"errors"
	"fmt"

	"github.com/luiky/mock-bank/internal/opf/resource"
	"github.com/luiky/mock-bank/internal/page"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{db: db}
}

func (s Service) Authorize(ctx context.Context, accIDs []string, consentID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, accID := range accIDs {
			var account Account
			if err := tx.First(&account, "id = ?", accID).Error; err != nil {
				return fmt.Errorf("account %s not found: %w", accID, err)
			}

			status := resource.StatusAvailable
			if account.IsJoint() {
				status = resource.StatusPendingAuthorization
			}

			if err := tx.Create(&ConsentAccount{
				ConsentID: consentID,
				AccountID: accID,
				Status:    status,
			}).Error; err != nil {
				return fmt.Errorf("could not create consent account resource: %w", err)
			}
		}

		return nil
	})
}

func (s Service) Save(ctx context.Context, acc *Account) error {
	if err := s.db.WithContext(ctx).Save(acc).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (s Service) consentedAccount(ctx context.Context, consentID, accountID, orgID string) (*Account, error) {
	acc := &Account{}
	err := s.db.WithContext(ctx).
		Joins("JOIN consent_resources ON consent_resources.resource_id = accounts.id").
		Where(`
			accounts.id = ? AND
			accounts.org_id = ? AND
			consent_resources.consent_id = ?`,
			accountID, orgID, consentID,
		).
		First(acc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errNotAllowed
	}
	return acc, err
}

func (s Service) Accounts(ctx context.Context, userID, orgID string) ([]Account, error) {
	var accounts []Account
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND org_id = ?", userID, orgID).
		Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("could not find accounts: %w", err)
	}
	return accounts, nil
}

func (s Service) consentedAccounts(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*Account], error) {
	query := s.db.WithContext(ctx).
		Model(&Account{}).
		Joins("JOIN consent_resources ON consent_resources.resource_id = accounts.id").
		Where("consent_resources.consent_id = ? AND org_id = ?", consentID, orgID)

	var accounts []*Account
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("accounts.created_at DESC").
		Find(&accounts).Error; err != nil {
		return page.Page[*Account]{}, fmt.Errorf("could not find consented accounts: %w", err)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Account]{}, fmt.Errorf("count failed: %w", err)
	}

	return page.New(accounts, pag, int(total)), nil
}

func (s Service) saveTransaction(ctx context.Context, tx *Transaction) error {
	return s.db.WithContext(ctx).Save(tx).Error
}

func (s Service) transactions(
	ctx context.Context,
	accID, orgID string,
	pag page.Pagination,
	filter transactionFilter,
) (
	page.Page[*Transaction],
	error,
) {
	query := s.db.WithContext(ctx).Model(&Transaction{}).Where("account_id = ? AND org_id = ?", accID, orgID)

	var txs []*Transaction
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&txs).Error; err != nil {
		return page.Page[*Transaction]{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Transaction]{}, err
	}

	return page.New(txs, pag, int(total)), nil
}

func (s Service) consentedTransactions(
	ctx context.Context,
	accID, consentID, orgID string,
	pag page.Pagination,
	filter transactionFilter,
) (
	page.Page[*Transaction],
	error,
) {
	var txs []*Transaction

	// TODO: Filter status.
	query := s.db.WithContext(ctx).Model(&Transaction{}).
		Joins("JOIN consent_resources ON consent_resources.resource_id = transactions.account_id").
		Where(`
			consent_resources.status = ? AND
			transactions.account_id = ? AND
			transactions.org_id = ? AND
			consent_resources.consent_id = ?`,
			resource.StatusAvailable, accID, orgID, consentID)

	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("transactions.created_at DESC").
		Find(&txs).Error; err != nil {
		return page.Page[*Transaction]{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Transaction]{}, err
	}

	return page.New(txs, pag, int(total)), nil
}
