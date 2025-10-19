package account

import (
	"context"
	"errors"
	"fmt"

	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Storage interface {
	create(ctx context.Context, acc *Account) error
	update(ctx context.Context, acc *Account) error
	account(ctx context.Context, query Query, orgID string) (*Account, error)
	accounts(ctx context.Context, orgID string, opts *Filter, pag page.Pagination) (page.Page[*Account], error)
	delete(ctx context.Context, id string, orgID string) error
	createConsent(ctx context.Context, consentAcc *ConsentAccount) error
	updateConsent(ctx context.Context, consentAcc *ConsentAccount) error
	consentAccount(ctx context.Context, accountID, consentID, orgID string) (*ConsentAccount, error)
	consentAccounts(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*ConsentAccount], error)
	transactions(ctx context.Context, accountID, orgID string, filter *TransactionFilter, pag page.Pagination) (page.Page[*Transaction], error)
}

type storage struct {
	db        *gorm.DB
	mockOrgID string
}

func (s storage) create(ctx context.Context, acc *Account) error {
	tx := s.db.WithContext(ctx).Create(acc)
	if err := tx.Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		return err
	}

	return nil
}

func (s storage) update(ctx context.Context, acc *Account) error {
	tx := s.db.WithContext(ctx).
		Model(&Account{}).
		Omit("ID", "CreatedAt", "OrgID").
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "created_at"}}}).
		Where("id = ? AND org_id = ?", acc.ID, acc.OrgID).
		Updates(acc)

	if err := tx.Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("could not update account: %w", err)
	}

	if tx.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s storage) account(ctx context.Context, query Query, orgID string) (*Account, error) {
	dbQuery := s.db.WithContext(ctx).Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", query.ID)
	}
	if query.Number != "" {
		dbQuery = dbQuery.Where("number = ?", query.Number)
	}

	acc := &Account{}
	if err := dbQuery.First(acc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("could not fetch account: %w", err)
	}
	return acc, nil
}

func (s storage) accounts(ctx context.Context, orgID string, opts *Filter, pag page.Pagination) (page.Page[*Account], error) {
	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Order("created_at DESC")

	if opts == nil {
		opts = &Filter{}
	}
	if opts.OwnerID != "" {
		query = query.Where("owner_id = ?", opts.OwnerID)
	}

	accounts, err := page.Paginate[*Account](query, pag)
	if err != nil {
		return page.Page[*Account]{}, fmt.Errorf("could not find accounts: %w", err)
	}

	return accounts, nil
}

func (s storage) delete(ctx context.Context, id string, orgID string) error {
	if err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).Delete(&Account{}).Error; err != nil {
		return fmt.Errorf("could not delete account: %w", err)
	}
	return nil
}

func (s storage) createConsent(ctx context.Context, consentAcc *ConsentAccount) error {
	if err := s.db.WithContext(ctx).Create(consentAcc).Error; err != nil {
		return fmt.Errorf("could not create consent account: %w", err)
	}
	return nil
}

func (s storage) updateConsent(ctx context.Context, consentAcc *ConsentAccount) error {
	tx := s.db.WithContext(ctx).
		Model(&Account{}).
		Omit("ID", "CreatedAt", "OrgID").
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "created_at"}}}).
		Where("account_id = ? AND consent_id = ? AND org_id = ?", consentAcc.AccountID, consentAcc.ConsentID, consentAcc.OrgID).
		Updates(consentAcc)

	if err := tx.Error; err != nil {
		return fmt.Errorf("could not update consent account: %w", err)
	}

	return nil
}

func (s storage) consentAccount(ctx context.Context, accountID, consentID, orgID string) (*ConsentAccount, error) {
	consentAcc := &ConsentAccount{}
	if err := s.db.WithContext(ctx).
		Preload("Account").
		Where(`account_id = ? AND consent_id = ? AND org_id = ?`, accountID, consentID, orgID).
		First(consentAcc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("could not fetch consent account: %w", err)
	}
	return consentAcc, nil
}

func (s storage) consentAccounts(ctx context.Context, consentID, orgID string, pag page.Pagination) (page.Page[*ConsentAccount], error) {
	query := s.db.WithContext(ctx).
		Model(&ConsentAccount{}).
		Preload("Account").
		Where(`org_id = ? AND consent_id = ?`, orgID, consentID).
		Where("status = ?", resource.StatusAvailable).
		Order("created_at DESC")

	consentAccs, err := page.Paginate[*ConsentAccount](query, pag)
	if err != nil {
		return page.Page[*ConsentAccount]{}, fmt.Errorf("failed to find consented accounts: %w", err)
	}

	return consentAccs, nil
}

func (s storage) transactions(ctx context.Context, accountID, orgID string, filter *TransactionFilter, pag page.Pagination) (page.Page[*Transaction], error) {
	query := s.db.WithContext(ctx).
		Model(&Transaction{}).
		Where("account_id = ? AND org_id = ? OR (org_id = ? AND cross_org = true)", accountID, orgID, s.mockOrgID)

	if filter == nil {
		filter = &TransactionFilter{}
	}

	if !filter.from.IsZero() {
		query = query.Where("date_time >= ?", filter.from.DateTime())
	}

	if !filter.to.IsZero() {
		query = query.Where("date_time <= ?", filter.to.DateTime())
	}

	if filter.movementType != "" {
		query = query.Where("movement_type = ?", filter.movementType)
	}

	txs, err := page.Paginate[*Transaction](query, pag)
	if err != nil {
		return page.Page[*Transaction]{}, fmt.Errorf("could not find transactions: %w", err)
	}

	return txs, nil
}
