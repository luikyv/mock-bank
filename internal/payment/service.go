package payment

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/errorutil"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"gorm.io/gorm"
)

const endToEndTimeFormat = "200601021504" // yyyyMMddHHmm.

type Service struct {
	db             *gorm.DB
	userService    user.Service
	accountService account.Service
}

func NewService(db *gorm.DB, userService user.Service, accountService account.Service) Service {
	return Service{db: db, userService: userService, accountService: accountService}
}

func (s Service) CreateConsent(ctx context.Context, c *Consent, debtorAcc *DebtorAccount) error {
	if err := s.validateConsent(ctx, c, debtorAcc); err != nil {
		return err
	}

	c.Status = ConsentStatusAwaitingAuthorization
	c.ExpiresAt = timeutil.DateTimeNow().Add(5 * time.Minute)

	u, err := s.userService.UserByCPF(ctx, c.UserCPF, c.OrgID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	c.UserID = u.ID

	if debtorAcc == nil {
		return s.createConsent(ctx, c)
	}

	acc, err := s.accountService.AccountByNumber(ctx, debtorAcc.Number, c.OrgID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return ErrAccountNotFound
		}
		return err
	}

	if acc.UserID != u.ID {
		return ErrUserDoesntMatchAccount
	}

	c.DebtorAccountID = &acc.ID
	return s.createConsent(ctx, c)
}

func (s Service) createConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Create(c).Error
}

func (s Service) validateConsent(ctx context.Context, c *Consent, debtorAccount *DebtorAccount) error {
	if debtorAccount != nil && c.CreditorAccountISBP == debtorAccount.ISBP && c.CreditorAccountNumber == debtorAccount.Number {
		return ErrCreditorAndDebtorAccountsAreEqual
	}

	if (c.PaymentDate != nil && c.PaymentSchedule != nil) || (c.PaymentDate == nil && c.PaymentSchedule == nil) {
		slog.DebugContext(ctx, "invalid consent: must provide either date or schedule, but not both")
		return ErrInvalidData
	}

	if c.PaymentSchedule != nil && c.PaymentSchedule.Single == nil {
		if !slices.Contains([]LocalInstrument{
			LocalInstrumentMANU,
			LocalInstrumentDICT,
			LocalInstrumentQRES,
		}, c.LocalInstrument) {
			slog.DebugContext(ctx, "invalid consent: only MANU, DICT or QRES are allowed when using schedule other than single",
				"localInstrument", c.LocalInstrument)
			return ErrInvalidData
		}
	}

	if c.LocalInstrument == LocalInstrumentMANU && c.Proxy != nil {
		slog.DebugContext(ctx, "invalid consent: proxy must not be set when using local instrument MANU",
			"localInstrument", c.LocalInstrument)
		return ErrInvalidData
	}

	if slices.Contains([]LocalInstrument{
		LocalInstrumentINIC,
		LocalInstrumentDICT,
		LocalInstrumentQRDN,
		LocalInstrumentQRES,
	}, c.LocalInstrument) && c.Proxy == nil {
		slog.DebugContext(ctx, "invalid consent: proxy must be set when using localInstrument INIC, DICT, QRDN or QRES",
			"localInstrument", c.LocalInstrument)
		return ErrInvalidData
	}

	if slices.Contains([]AccountType{
		AccountTypeCACC,
		AccountTypeSVGS,
	}, c.CreditorAccountType) && c.CreditorAccountIssuer == nil {
		slog.DebugContext(ctx, "invalid consent: creditor account issuer is required for account types CACC or SVGS",
			"accountType", c.CreditorAccountType)
		return ErrInvalidData
	}

	return nil
}

func (s Service) AuthorizeConsent(ctx context.Context, c *Consent) error {

	if !c.IsAwaitingAuthorization() {
		return errors.New("consent is not awaiting authorization")
	}

	c.Status = ConsentStatusAuthorized
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	return s.saveConsent(ctx, c)
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
	c := &Consent{}
	if err := s.db.WithContext(ctx).Preload("DebtorAccount").First(c, "id = ? AND org_id = ?", id, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != c.ClientID {
		return nil, ErrClientNotAllowed
	}

	if err := s.modifyConsent(ctx, c); err != nil {
		return nil, err
	}

	return c, nil
}

// modifyConsent will evaluated the payment consent information and modify it to be compliant.
func (s Service) modifyConsent(ctx context.Context, c *Consent) error {
	if c.HasAuthExpired() {
		slog.DebugContext(ctx, "payment consent awaiting authorization for too long, moving to rejected")
		return s.rejectConsent(ctx, c, RejectionReasonCodeAuthorizationTimeout, "consent awaiting authorization for too long")
	}

	if c.IsExpired() {
		slog.DebugContext(ctx, "payment consent reached expiration, moving to rejected")
		return s.rejectConsent(ctx, c, RejectionReasonCodeConsumptionTimeout, "payment consent authorization reached expiration")
	}

	return nil
}

func (s Service) RejectConsent(ctx context.Context, id, orgID string, code RejectionReasonCode, detail string) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	return s.rejectConsent(ctx, c, code, detail)
}

func (s Service) rejectConsent(ctx context.Context, c *Consent, code RejectionReasonCode, detail string) error {
	if c.Status == ConsentStatusRejected {
		return ErrConsentAlreadyRejected
	}

	c.Status = ConsentStatusRejected
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	c.RejectionReasonCode = code
	c.RejectionReasonDetail = detail
	return s.saveConsent(ctx, c)
}

func (s Service) saveConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Save(c).Error
}

func (s Service) Create(ctx context.Context, payments []*Payment) error {
	firstPayment := payments[0]
	consentID := firstPayment.ConsentID.String()
	orgID := firstPayment.OrgID
	c, err := s.Consent(ctx, consentID, orgID)
	if err != nil {
		return err
	}

	if !c.IsAuthorized() {
		return ErrConsentNotAuthorized
	}

	if err := s.validate(ctx, c, payments); err != nil {
		return err
	}

	for _, p := range payments {
		p.Status = StatusRCVD
		p.DebtorAccountID = c.DebtorAccountID
		p.DebtorAccount = c.DebtorAccount
		date, _ := ParseEndToEndDate(p.EndToEndID)
		p.Date = date.BrazilDate()
	}
	return s.db.Create(&payments).Error
}

func (s Service) validate(_ context.Context, c *Consent, payments []*Payment) error {
	dates := c.PaymentDates()
	if len(dates) != len(payments) {
		return errorutil.Format("number of payments doesn't match schedule. got %d, expected %d", len(payments), len(dates))
	}

	for _, p := range payments {
		endToEndDate, err := ParseEndToEndDate(p.EndToEndID)
		if err != nil {
			return errorutil.Format("%w: invalid end to end id date: %w", ErrInvalidEndToEndID, err)
		}

		if !slices.ContainsFunc(dates, func(d timeutil.BrazilDate) bool {
			return endToEndDate.BrazilDate().Equal(d)
		}) {
			return errorutil.Format("%w: end to end id date doesn't match any of the scheduled dates", ErrInvalidEndToEndID)
		}
	}

	return nil
}

func (s Service) Payment(ctx context.Context, id, orgID string) (*Payment, error) {
	p := &Payment{}
	if err := s.db.WithContext(ctx).Preload("DebtorAccount").First(p, "id = ? AND org_id = ?", id, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != p.ClientID {
		return nil, ErrClientNotAllowed
	}

	if err := s.modify(ctx, p); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) modify(ctx context.Context, p *Payment) error {
	now := timeutil.Now()
	if now.Before(p.UpdatedAt.Time.Add(30 * time.Second)) {
		slog.DebugContext(ctx, "payment was updated less than 30 secs ago, skipping transitions", "updated_at", p.UpdatedAt.String())
		return nil
	}

	slog.DebugContext(ctx, "payment is "+string(p.Status))

	if p.Status == StatusRCVD {
		slog.DebugContext(ctx, "moving payment to ACCP")
		return s.updateStatus(ctx, p, StatusACCP)
	}

	if p.Status == StatusACCP {
		now := timeutil.BrazilDateNow()
		if p.Date.After(now) {
			slog.DebugContext(ctx, "moving payment to SCHD")
			return s.updateStatus(ctx, p, StatusSCHD)
		}

		slog.DebugContext(ctx, "moving payment to ACPD")
		return s.updateStatus(ctx, p, StatusACPD)
	}

	if p.Status == StatusSCHD {
		now := timeutil.BrazilDateNow()
		if p.Date.After(now) {
			return nil
		}
		slog.DebugContext(ctx, "moving payment to ACPD")
		return s.updateStatus(ctx, p, StatusACPD)
	}

	if p.Status == StatusACPD {
		slog.DebugContext(ctx, "moving payment to ACSC")
		return s.updateStatus(ctx, p, StatusACSC)
	}

	return nil
}

func (s Service) updateStatus(ctx context.Context, p *Payment, status Status) error {
	p.Status = status
	p.StatusUpdatedAt = timeutil.DateTimeNow()
	p.UpdatedAt = timeutil.DateTimeNow()
	return s.save(ctx, p)
}

func (s Service) save(ctx context.Context, p *Payment) error {
	return s.db.WithContext(ctx).Save(p).Error
}

// ParseEndToEndDate extracts and parses the datetime (yyyyMMddHHmm) from an end to end ID.
func ParseEndToEndDate(id string) (timeutil.DateTime, error) {
	dateStr := id[9:21]
	parsed, err := time.ParseInLocation(endToEndTimeFormat, dateStr, time.UTC)
	if err != nil {
		return timeutil.DateTime{}, err
	}

	return timeutil.NewDateTime(parsed), nil
}
