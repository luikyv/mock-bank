package account

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
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

func (s Service) Authorize(ctx context.Context, accIDs []string, consentID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, accID := range accIDs {
			var acc Account
			if err := tx.First(&acc, "id = ?", accID).Error; err != nil {
				return fmt.Errorf("account %s not found: %w", accID, err)
			}

			status := resource.StatusAvailable
			if acc.SubType == SubTypeJointSimple {
				status = resource.StatusPendingAuthorization
			}

			if err := s.createConsent(ctx, &ConsentAccount{
				ConsentID: consentID,
				AccountID: accID,
				Status:    status,
				OrgID:     acc.OrgID,
			}); err != nil {
				return fmt.Errorf("could not create resource for account: %w", err)
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

func (s Service) createConsent(ctx context.Context, consentAcc *ConsentAccount) error {
	return s.db.WithContext(ctx).Create(consentAcc).Error
}

func (s Service) ConsentedAccount(ctx context.Context, accountID, consentID, orgID string) (*Account, error) {
	consentAcc := &ConsentAccount{}
	if err := s.db.WithContext(ctx).
		Preload("Account").
		Where(`account_id = ? AND consent_id = ? AND org_id = ? AND status = ?`, accountID, consentID, orgID, resource.StatusAvailable).
		First(consentAcc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotAllowed
		}
		return nil, err
	}

	return consentAcc.Account, nil
}

func (s Service) AllAccounts(ctx context.Context, userID, orgID string) ([]Account, error) {
	var accounts []Account
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND org_id = ?", userID, orgID).
		Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("could not find accounts: %w", err)
	}
	return accounts, nil
}

func (s Service) Accounts(ctx context.Context, userID, orgID string, pag page.Pagination) (page.Page[*Account], error) {
	query := s.db.WithContext(ctx).Where("user_id = ? AND org_id = ?", userID, orgID)

	var accounts []*Account
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&accounts).Error; err != nil {
		return page.Page[*Account]{}, fmt.Errorf("could not find consented accounts: %w", err)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Account]{}, fmt.Errorf("count failed: %w", err)
	}

	return page.New(accounts, pag, int(total)), nil
}

func (s Service) ConsentedAccounts(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*Account], error) {
	query := s.db.WithContext(ctx).
		Model(&ConsentAccount{}).
		Preload("Account").
		Where(`org_id = ? AND consent_id = ? AND status = ?`, orgID, consentID, resource.StatusAvailable)

	var consentAccs []*ConsentAccount
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&consentAccs).Error; err != nil {
		return page.Page[*Account]{}, fmt.Errorf("could not find consented accounts: %w", err)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Account]{}, fmt.Errorf("count failed: %w", err)
	}

	var accs []*Account
	for _, consentAcc := range consentAccs {
		accs = append(accs, consentAcc.Account)
	}
	return page.New(accs, pag, int(total)), nil
}

func (s Service) Delete(ctx context.Context, id, orgID string) error {
	return s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).Delete(&Account{}).Error
}

func (s Service) CreateTransaction(ctx context.Context, tx *Transaction) error {
	return s.db.WithContext(ctx).Create(tx).Error
}

func (s Service) Transactions(ctx context.Context, accID, orgID string, pag page.Pagination, filter TransactionFilter) (page.Page[*Transaction], error) {
	query := s.db.WithContext(ctx).
		Model(&Transaction{}).
		Where("account_id = ? AND org_id = ? AND created_at >= ? AND created_at < ?",
			accID, orgID, filter.from.Time, filter.to.Time)

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

func (s Service) ConsentedTransactions(ctx context.Context, accID, consentID, orgID string, pag page.Pagination, filter TransactionFilter) (page.Page[*Transaction], error) {
	var txs []*Transaction

	query := s.db.WithContext(ctx).Model(&Transaction{}).
		Joins("JOIN consent_accounts ON consent_accounts.account_id = account_transactions.account_id").
		Where(`
			account_transactions.account_id = ? AND
			account_transactions.org_id = ? AND
			account_transactions.created_at >= ? AND
			account_transactions.created_at < ? AND
			consent_accounts.consent_id = ? AND
			consent_accounts.status = ?`,
			accID, orgID, filter.from.Time, filter.to.Time, consentID, resource.StatusAvailable)

	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("account_transactions.created_at DESC").
		Find(&txs).Error; err != nil {
		return page.Page[*Transaction]{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Transaction]{}, err
	}

	return page.New(txs, pag, int(total)), nil
}
