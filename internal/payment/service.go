package payment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
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

func (s Service) CreateConsent(ctx context.Context, c *Consent, debtorAcc *Account) error {
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

	if err := s.runConsentPreCreationAutomations(ctx, c); err != nil {
		return err
	}

	return s.createConsent(ctx, c)
}

func (s Service) AuthorizeConsent(ctx context.Context, c *Consent) error {

	if !c.IsAwaitingAuthorization() {
		return errorutil.New("consent is not awaiting authorization")
	}

	c.ExpiresAt = timeutil.DateTimeNow().Add(60 * time.Minute)
	return s.updateConsentStatus(ctx, c, ConsentStatusAuthorized)
}

func (s Service) UpdateDebtorAccount(ctx context.Context, consentID, accountID, orgID string) error {
	c, err := s.Consent(ctx, consentID, orgID)
	if err != nil {
		return err
	}

	accID := uuid.MustParse(accountID)
	c.DebtorAccountID = &accID
	c.UpdatedAt = timeutil.DateTimeNow()
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

	if err := s.runConsentPostCreationAutomations(ctx, c); err != nil {
		return nil, err
	}

	return c, nil
}

func (s Service) RejectConsent(ctx context.Context, id, orgID string, code ConsentRejectionReasonCode, detail string) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	return s.rejectConsent(ctx, c, code, detail)
}

func (s Service) CreatePayments(ctx context.Context, payments []*Payment) error {

	firstPayment := payments[0]
	consentID := firstPayment.ConsentID.String()
	if consentID == uuid.Nil.String() {
		return errorutil.New("invalid payment: could not infer consent id")
	}

	orgID := firstPayment.OrgID
	c, err := s.Consent(ctx, consentID, orgID)
	if err != nil {
		return err
	}

	if !c.IsAuthorized() {
		return ErrConsentNotAuthorized
	}

	if err := s.updateConsentStatus(ctx, c, ConsentStatusConsumed); err != nil {
		return err
	}

	if err := s.validatePayments(ctx, c, payments); err != nil {
		return err
	}

	for _, p := range payments {
		p.Status = StatusRCVD
		p.DebtorAccountID = c.DebtorAccountID
		p.DebtorAccount = c.DebtorAccount
		date, _ := ParseEndToEndDate(p.EndToEndID)
		p.Date = date.BrazilDate()

		if err := s.runPreCreationAutomations(ctx, p); err != nil {
			return err
		}
	}
	return s.db.Create(&payments).Error
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

	if err := s.runPostCreationAutomations(ctx, p); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) Cancel(ctx context.Context, id, orgID string, doc Document) (*Payment, error) {
	p, err := s.Payment(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	c, err := s.Consent(ctx, p.ConsentID.String(), orgID)
	if err != nil {
		return nil, err
	}

	if doc.Rel != "CPF" {
		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
	}

	if c.UserCPF != doc.Identification {
		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
	}

	if err := s.cancel(ctx, p, CancelledFromInitiator, c.UserCPF); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) CancelAll(ctx context.Context, consentID, orgID string, doc Document) ([]*Payment, error) {
	c, err := s.Consent(ctx, consentID, orgID)
	if err != nil {
		return nil, err
	}

	if doc.Rel != "CPF" {
		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
	}

	if c.UserCPF != doc.Identification {
		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
	}

	var payments []*Payment
	if err := s.db.WithContext(ctx).
		Where("consent_id = ? AND org_id = ?", c.ID, orgID).
		Find(&payments).Error; err != nil {
		return nil, fmt.Errorf("could not find payments: %w", err)
	}

	var cancelled []*Payment
	var cancelErrs error
	for _, p := range payments {
		if err := s.cancel(ctx, p, CancelledFromInitiator, c.UserCPF); err != nil {
			if !errors.Is(err, ErrCancelNotAllowed) {
				return nil, err
			}
			cancelErrs = errors.Join(cancelErrs, err)
			continue
		}
		cancelled = append(cancelled, p)
	}

	if len(cancelled) == 0 {
		return nil, errorutil.Format("no payment could be cancelled: %w", cancelErrs)
	}

	return cancelled, nil
}

func (s Service) cancel(ctx context.Context, p *Payment, from CancelledFrom, by string) error {
	if !slices.Contains([]Status{StatusPDNG, StatusSCHD}, p.Status) {
		return errorutil.Format("%w: payment with status %s cannot be cancelled, only payments with status PDNG or SCHD can be cancelled", ErrCancelNotAllowed, p.Status)
	}

	if p.Status == StatusSCHD && !timeutil.BrazilDateNow().Before(p.Date) {
		return errorutil.Format("%w: scheduled payments can only be cancelled until 23:59 (BRT) of the day before the payment date (%s)", ErrCancelNotAllowed, p.Date.String())
	}

	reason := CancellationReasonPending
	if p.Status == StatusSCHD {
		reason = CancellationReasonScheduled
	}
	p.Cancellation = &Cancellation{
		At:     timeutil.DateTimeNow(),
		Reason: reason,
		From:   from,
		By:     by,
	}
	return s.updateStatus(ctx, p, StatusCANC)
}

func (s Service) createConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Create(c).Error
}

func (s Service) validateConsent(_ context.Context, c *Consent, debtorAccount *Account) error {
	if debtorAccount != nil && c.CreditorAccountISBP == debtorAccount.ISPB && c.CreditorAccountNumber == debtorAccount.Number {
		return ErrCreditorAndDebtorAccountsAreEqual
	}

	if c.PaymentDate == nil && c.PaymentSchedule == nil {
		return errorutil.Format("%w: must provide either date or schedule", ErrMissingValue)
	}

	if (c.PaymentDate != nil && c.PaymentSchedule != nil) || (c.PaymentDate == nil && c.PaymentSchedule == nil) {
		return errorutil.Format("%w: cannot provide both date and schedule", ErrInvalidDate)
	}

	if c.PaymentSchedule != nil {
		today := timeutil.BrazilDateNow()
		twoYearsLater := today.AddDate(2, 0, 0)

		startDate := today
		lastPaymentDate := twoYearsLater
		if single := c.PaymentSchedule.Single; single != nil {
			startDate = single.Date
			lastPaymentDate = single.Date
		}

		if daily := c.PaymentSchedule.Daily; daily != nil {
			startDate = daily.StartDate
			lastPaymentDate = daily.StartDate.AddDate(0, 0, daily.Quantity-1)
		}

		if weekly := c.PaymentSchedule.Weekly; weekly != nil {
			startDate = weekly.StartDate
			lastPaymentDate = weekly.StartDate.AddDate(0, 0, 7*(weekly.Quantity-1))
		}

		if monthly := c.PaymentSchedule.Monthly; monthly != nil {
			startDate = monthly.StartDate
			lastPaymentDate = monthly.StartDate.AddDate(0, monthly.Quantity-1, 0)
		}

		if custom := c.PaymentSchedule.Custom; custom != nil {
			seenDates := map[string]struct{}{}
			for _, date := range custom.Dates {
				dateStr := date.String()

				if _, exists := seenDates[dateStr]; exists {
					return errorutil.Format("%w: custom schedule contains duplicate date: %s", ErrInvalidData, dateStr)
				}
				seenDates[dateStr] = struct{}{}

				if date.Before(startDate) {
					startDate = date
				}
				if date.After(lastPaymentDate) {
					lastPaymentDate = date
				}
			}
		}

		if !startDate.After(today) {
			return errorutil.Format("%w: schedule must be after the current day", ErrInvalidDate)
		}
		if !lastPaymentDate.Before(twoYearsLater) {
			return errorutil.Format("%w: schedule exceeds 2-year window", ErrInvalidDate)
		}

	}

	if c.PaymentSchedule != nil && c.PaymentSchedule.Single == nil && !slices.Contains([]LocalInstrument{
		LocalInstrumentMANU,
		LocalInstrumentDICT,
		LocalInstrumentQRES,
	}, c.LocalInstrument) {
		return errorutil.New("only MANU, DICT or QRES are allowed when using schedule other than single")
	}

	if c.LocalInstrument == LocalInstrumentMANU && c.Proxy != nil {
		return errorutil.New("proxy must not be set when using local instrument MANU")
	}

	if slices.Contains([]LocalInstrument{
		LocalInstrumentINIC,
		LocalInstrumentDICT,
		LocalInstrumentQRDN,
		LocalInstrumentQRES,
	}, c.LocalInstrument) && c.Proxy == nil {
		return errorutil.New("proxy must be set when using localInstrument INIC, DICT, QRDN or QRES")
	}

	if slices.Contains([]AccountType{
		AccountTypeCACC,
		AccountTypeSVGS,
	}, c.CreditorAccountType) && c.CreditorAccountIssuer == nil {
		return errorutil.New("creditor account issuer is required for account types CACC or SVGS")
	}

	if debtorAccount != nil && slices.Contains([]AccountType{
		AccountTypeCACC,
		AccountTypeSVGS,
	}, debtorAccount.Type) && debtorAccount.Issuer == nil {
		return errorutil.New("debtor account issuer is required for account types CACC or SVGS")
	}

	return nil
}

func (s Service) updateConsentStatus(ctx context.Context, c *Consent, status ConsentStatus) error {
	c.Status = status
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	c.UpdatedAt = timeutil.DateTimeNow()
	return s.saveConsent(ctx, c)
}

func (s Service) runConsentPreCreationAutomations(_ context.Context, c *Consent) error {
	switch c.PaymentAmount {
	case "10422.00":
		return ErrInvalidPayment
	default:
		return nil
	}
}

func (s Service) runConsentPostCreationAutomations(ctx context.Context, c *Consent) error {
	switch c.Status {
	case ConsentStatusAwaitingAuthorization:
		if c.IsExpired() {
			slog.DebugContext(ctx, "payment consent awaiting authorization for too long, moving to rejected")
			return s.rejectConsent(ctx, c, ConsentRejectionAuthorizationTimeout, "consent awaiting authorization for too long")
		}

		switch c.PaymentAmount {
		case "300.01":
			return s.rejectConsent(ctx, c, ConsentRejectionInvalidAmount, "forced rejection")
		case "300.02":
			return s.rejectConsent(ctx, c, ConsentRejectionNotProvided, "forced rejection")
		case "300.03":
			return s.rejectConsent(ctx, c, ConsentRejectionInfrastructureFailure, "forced rejection")
		case "300.04":
			return s.rejectConsent(ctx, c, ConsentRejectionConsumptionTimeout, "forced rejection")
		case "300.05":
			return s.rejectConsent(ctx, c, ConsentRejectionAccountDoesNotAllowPayment, "forced rejection")
		case "300.06":
			return s.rejectConsent(ctx, c, ConsentRejectionInsufficientFunds, "forced rejection")
		case "300.07":
			return s.rejectConsent(ctx, c, ConsentRejectionAmountAboveLimit, "forced rejection")
		case "300.08":
			return s.rejectConsent(ctx, c, ConsentRejectionInvalidQRCode, "forced rejection")
		default:
			return nil
		}

	case ConsentStatusAuthorized:
		if c.IsExpired() {
			slog.DebugContext(ctx, "payment consent reached expiration, moving to rejected")
			return s.rejectConsent(ctx, c, ConsentRejectionConsumptionTimeout, "payment consent authorization reached expiration")
		}
		return nil
	default:
		return nil
	}
}

func (s Service) rejectConsent(ctx context.Context, c *Consent, code ConsentRejectionReasonCode, detail string) error {
	if c.Status == ConsentStatusRejected {
		return ErrConsentAlreadyRejected
	}

	c.Rejection = &ConsentRejection{
		Code:   code,
		Detail: detail,
	}
	return s.updateConsentStatus(ctx, c, ConsentStatusRejected)
}

func (s Service) saveConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Save(c).Error
}

func (s Service) validatePayments(_ context.Context, c *Consent, payments []*Payment) error {
	dates := c.PaymentDates()
	if len(dates) != len(payments) {
		return errorutil.Format("%w: number of payments doesn't match schedule. got %d, expected %d", ErrPaymentDoesNotMatchConsent, len(payments), len(dates))
	}

	consentID := payments[0].ConsentID

	for _, p := range payments {
		if p.ConsentID != consentID {
			return errorutil.New("invalid payment: invalid consent id")
		}

		endToEndDate, err := ParseEndToEndDate(p.EndToEndID)
		if err != nil {
			return errorutil.Format("%w: invalid end to end id date: %w", ErrInvalidEndToEndID, err)
		}

		// TODO: What if all end to end dates are for a same date and don't respect the schedule?
		if !slices.ContainsFunc(dates, func(d timeutil.BrazilDate) bool {
			return endToEndDate.BrazilDate().Equal(d)
		}) {
			return errorutil.Format("%w: end to end id date doesn't match any of the scheduled dates", ErrInvalidEndToEndID)
		}

		if p.LocalInstrument != c.LocalInstrument {
			return errorutil.Format("%w: local instrument does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if p.Amount != c.PaymentAmount {
			return errorutil.Format("%w: amount does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if p.Currency != c.PaymentCurrency {
			return errorutil.Format("%w: currency does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if p.CreditorAccountISBP != c.CreditorAccountISBP {
			return errorutil.Format("%w: creditor account isbp does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if !reflect.DeepEqual(p.CreditorAccountIssuer, c.CreditorAccountIssuer) {
			return errorutil.Format("%w: creditor account issuer does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if p.CreditorAccountNumber != c.CreditorAccountNumber {
			return errorutil.Format("%w: creditor account number does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if p.CreditorAccountType != c.CreditorAccountType {
			return errorutil.Format("%w: creditor account type does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if !reflect.DeepEqual(p.QRCode, c.QRCode) {
			return errorutil.Format("%w: qr code does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if !reflect.DeepEqual(p.Proxy, c.Proxy) {
			return errorutil.Format("%w: proxy does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
		}

		if slices.Contains([]LocalInstrument{
			LocalInstrumentMANU,
			LocalInstrumentDICT,
		}, p.LocalInstrument) && p.TransactionIdentification != nil {
			return errorutil.New("invalid consent: transaction identification is not allowed if local instrument is MANU or DICT")
		}
	}

	return nil
}

func (s Service) runPreCreationAutomations(_ context.Context, p *Payment) error {
	switch p.Amount {
	case "20422.01":
		return ErrInvalidPayment
	default:
		return nil
	}
}

func (s Service) runPostCreationAutomations(ctx context.Context, p *Payment) error {
	now := timeutil.Now()
	if now.Before(p.UpdatedAt.Time.Add(5 * time.Second)) {
		slog.DebugContext(ctx, "payment was updated less than 5 secs ago, skipping transitions", "updated_at", p.UpdatedAt.String())
		return nil
	}

	slog.DebugContext(ctx, "evaluating payment automations", "status", p.Status, "amount", p.Amount)

	switch p.Status {
	case StatusRCVD:
		return s.updateStatus(ctx, p, StatusACCP)

	case StatusACCP:
		today := timeutil.BrazilDateNow()
		if p.Date.After(today) {
			return s.updateStatus(ctx, p, StatusSCHD)
		}
		return s.updateStatus(ctx, p, StatusACPD)

	case StatusSCHD:
		today := timeutil.BrazilDateNow()
		if p.Date.After(today) {
			return nil
		}
		return s.updateStatus(ctx, p, StatusACPD)

	case StatusACPD:
		return s.updateStatus(ctx, p, StatusACSC)
	}

	return nil
}

func (s Service) updateStatus(ctx context.Context, p *Payment, status Status) error {
	slog.DebugContext(ctx, "updating payment status", "current_status", p.Status, "new_status", status)

	p.Status = status
	p.StatusUpdatedAt = timeutil.DateTimeNow()
	p.UpdatedAt = timeutil.DateTimeNow()
	return s.save(ctx, p)
}

func (s Service) save(ctx context.Context, p *Payment) error {
	return s.db.WithContext(ctx).Save(p).Error
}

func (s Service) reject(ctx context.Context, p *Payment, code RejectionReasonCode, detail string) error {
	p.Rejection = &Rejection{
		Code:   code,
		Detail: detail,
	}
	return s.updateStatus(ctx, p, StatusRJCT)
}
