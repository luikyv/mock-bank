package payment

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"gorm.io/gorm"
)

type Service struct {
	db             *gorm.DB
	userService    user.Service
	accountService account.Service
}

func NewService(db *gorm.DB, userService user.Service, accountService account.Service) Service {
	return Service{db: db, userService: userService, accountService: accountService}
}

func (s Service) CreateConsent(ctx context.Context, consent *Consent, debtorAcc *DebtorAccount) error {
	consent.Status = ConsentStatusAwaitingAuthorization
	consent.ExpiresAt = timeutil.Now().Add(5 * time.Minute)

	u, err := s.userService.UserByCPF(ctx, consent.UserCPF, consent.OrgID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	consent.UserID = u.ID

	if debtorAcc == nil {
		return s.db.Create(consent).Error
	}

	acc, err := s.accountService.AccountByNumber(ctx, debtorAcc.Number, consent.OrgID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return ErrAccountNotFound
		}
		return err
	}

	if acc.UserID != u.ID {
		return ErrUserDoesntMatchAccount
	}

	consent.DebtorAccountID = &acc.ID
	return s.db.Create(consent).Error
}

func (s Service) AuthorizeConsent(ctx context.Context, c *Consent) error {

	if !c.IsAwaitingAuthorization() {
		return errors.New("consent is not awaiting authorization")
	}

	c.Status = ConsentStatusAuthorized
	c.StatusUpdatedAt = timeutil.Now()
	return s.db.WithContext(ctx).Save(c).Error
}

func (s Service) UpdateDebtorAccount(ctx context.Context, consentID, accountID, orgID string) error {
	c, err := s.Consent(ctx, consentID, orgID)
	if err != nil {
		return err
	}

	accID := uuid.MustParse(accountID)
	c.DebtorAccountID = &accID
	return s.db.WithContext(ctx).Save(c).Error
}

func (s Service) Consent(ctx context.Context, id, orgID string) (*Consent, error) {
	id = strings.TrimPrefix(id, consent.URNPrefix)
	var consent Consent
	if err := s.db.WithContext(ctx).Preload("DebtorAccount").First(&consent, "id = ? AND org_id = ?", id, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrConsentNotFound
		}
		return nil, err
	}

	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != consent.ClientID {
		return nil, ErrAccessNotAllowed
	}

	return &consent, nil
}

func (s Service) RejectConsent(ctx context.Context, id, orgID string, code RejectionReasonCode, detail string) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}
	if c.Status == ConsentStatusRejected {
		return ErrConsentAlreadyRejected
	}

	c.Status = ConsentStatusRejected
	c.StatusUpdatedAt = timeutil.Now()
	c.RejectionReasonCode = code
	c.RejectionReasonDetail = detail
	return s.db.WithContext(ctx).Save(c).Error
}
