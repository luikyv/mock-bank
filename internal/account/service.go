package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

func (s Service) Authorize(ctx context.Context, accIDs []string, consentID, orgID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txService := s.WithTx(tx)
		for _, accID := range accIDs {
			acc, err := txService.Account(ctx, Query{ID: accID}, orgID)
			if err != nil {
				return err
			}

			status := resource.StatusAvailable
			if acc.SubType == SubTypeJointSimple {
				status = resource.StatusPendingAuthorization
			}

			if err := txService.createConsent(ctx, &ConsentAccount{
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
	})
}

func (s Service) Create(ctx context.Context, acc *Account) error {
	now := timeutil.DateTimeNow()
	acc.CreatedAt = now
	acc.UpdatedAt = now
	tx := s.db.WithContext(ctx).Create(acc)
	if err := tx.Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		return err
	}

	return nil
}

func (s Service) Update(ctx context.Context, acc *Account) error {
	acc.UpdatedAt = timeutil.DateTimeNow()
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
		return err
	}

	if tx.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s Service) UpdateConsent(ctx context.Context, consentID, accountID uuid.UUID, orgID string, status resource.Status) error {
	tx := s.db.WithContext(ctx).
		Model(&ConsentAccount{}).
		Where("consent_id = ? AND account_id = ? AND org_id = ?", consentID, accountID, orgID).
		Updates(map[string]any{
			"status":     status,
			"updated_at": timeutil.DateTimeNow(),
		})

	if tx.Error != nil {
		return fmt.Errorf("failed to update consent account: %w", tx.Error)
	}

	if tx.RowsAffected == 0 {
		return fmt.Errorf("no matching consent account found for consent_id=%s account_id=%s", consentID, accountID)
	}

	return nil
}

func (s Service) Account(ctx context.Context, query Query, orgID string) (*Account, error) {
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

func (s Service) Accounts(ctx context.Context, ownerID, orgID string, pag page.Pagination) (page.Page[*Account], error) {
	query := s.db.WithContext(ctx).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("owner_id = ?", ownerID).
		Order("created_at DESC")

	accounts, err := page.Paginate[*Account](query, pag)
	if err != nil {
		return page.Page[*Account]{}, fmt.Errorf("could not find consented accounts: %w", err)
	}

	return accounts, nil
}

func (s Service) ConsentedAccount(ctx context.Context, accountID, consentID, orgID string) (*Account, error) {
	consentAcc := &ConsentAccount{}
	if err := s.db.WithContext(ctx).
		Preload("Account").
		Where(`account_id = ? AND consent_id = ? AND org_id = ?`, accountID, consentID, orgID).
		First(consentAcc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotAllowed
		}
		return nil, fmt.Errorf("could not fetch consent account: %w", err)
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
	query := s.db.WithContext(ctx).
		Model(&ConsentAccount{}).
		Preload("Account").
		Where(`org_id = ? AND consent_id = ?`, orgID, consentID).
		// Only return accounts that are available or accounts that are pending authorization
		// and were updated more than 3 minutes ago.
		Where("status = ? OR (status = ? AND updated_at < ?)",
			resource.StatusAvailable, resource.StatusPendingAuthorization, timeutil.DateTimeNow().Add(-3*time.Minute)).
		Order("created_at DESC")

	consentAccs, err := page.Paginate[*ConsentAccount](query, pag)
	if err != nil {
		return page.Page[*Account]{}, fmt.Errorf("failed to find consented accounts: %w", err)
	}

	var accs []*Account
	for _, consentAcc := range consentAccs.Records {
		accs = append(accs, consentAcc.Account)
	}
	return page.New(accs, pag, consentAccs.TotalRecords), nil
}

func (s Service) Delete(ctx context.Context, id uuid.UUID, orgID string) error {
	if err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).Delete(&Account{}).Error; err != nil {
		return fmt.Errorf("could not delete account: %w", err)
	}

	return nil
}

func (s Service) Transactions(ctx context.Context, accID, orgID string, pag page.Pagination, filter TransactionFilter) (page.Page[*Transaction], error) {
	query := s.db.WithContext(ctx).
		Model(&Transaction{}).
		Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID).
		Where("account_id = ? AND date_time >= ? AND date_time <= ?", accID, filter.from.DateTime(), filter.to.DateTime())

	if filter.movementType != "" {
		query = query.Where("movement_type = ?", filter.movementType)
	}

	var txs []*Transaction
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("date_time DESC").
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
	if _, err := s.ConsentedAccount(ctx, accID, consentID, orgID); err != nil {
		return page.Page[*Transaction]{}, err
	}

	return s.Transactions(ctx, accID, orgID, pag, filter)
}

func (s Service) createConsent(ctx context.Context, consentAcc *ConsentAccount) error {
	now := timeutil.DateTimeNow()
	consentAcc.CreatedAt = now
	consentAcc.UpdatedAt = now
	if err := s.db.WithContext(ctx).Create(consentAcc).Error; err != nil {
		return fmt.Errorf("could not create consent account: %w", err)
	}

	return nil
}
