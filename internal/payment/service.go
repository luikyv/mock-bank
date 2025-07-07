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
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/schedule"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"github.com/luikyv/mock-bank/internal/webhook"
	"gorm.io/gorm"
)

type Service struct {
	db              *gorm.DB
	userService     user.Service
	accountService  account.Service
	webhookService  webhook.Service
	scheduleService schedule.Service
	version         string
}

func NewService(
	db *gorm.DB,
	userService user.Service,
	accountService account.Service,
	webhookService webhook.Service,
	scheduleService schedule.Service,
) Service {
	return Service{
		db:              db,
		userService:     userService,
		accountService:  accountService,
		webhookService:  webhookService,
		scheduleService: scheduleService,
		version:         "v0",
	}
}

func (s Service) WithVersion(version string) Service {
	s.version = version
	return s
}

func (s Service) CreateConsent(ctx context.Context, c *Consent, debtorAcc *Account) error {
	if err := s.validateConsent(ctx, c, debtorAcc); err != nil {
		return err
	}

	c.Status = ConsentStatusAwaitingAuthorization
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	c.ExpiresAt = timeutil.DateTimeNow().Add(5 * time.Minute)

	u, err := s.userService.User(ctx, user.Query{CPF: c.UserIdentification}, c.OrgID)
	if err != nil {
		return err
	}
	c.OwnerID = u.ID

	if c.BusinessIdentification != nil {
		business, err := s.userService.User(ctx, user.Query{CNPJ: *c.BusinessIdentification}, c.OrgID)
		if err != nil {
			return err
		}
		c.OwnerID = business.ID
	}

	if debtorAcc == nil {
		return s.db.WithContext(ctx).Create(c).Error
	}

	acc, err := s.accountService.Account(ctx, account.Query{Number: debtorAcc.Number}, c.OrgID)
	if err != nil {
		return err
	}

	if acc.OwnerID != c.OwnerID {
		return ErrUserDoesntMatchAccount
	}

	c.DebtorAccountID = &acc.ID

	if err := s.runConsentPreCreationAutomations(ctx, c); err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Create(c).Error; err != nil {
		return fmt.Errorf("could not create consent: %w", err)
	}

	return nil
}

func (s Service) AuthorizeConsent(ctx context.Context, c *Consent) error {

	if c.Status != ConsentStatusAwaitingAuthorization {
		return errorutil.Format("%w: consent is not awaiting authorization", ErrInvalidConsentStatus)
	}

	c.ExpiresAt = timeutil.DateTimeNow().Add(60 * time.Minute)

	// Load debtor account if not already loaded.
	if c.DebtorAccount == nil && c.DebtorAccountID != nil {
		acc, err := s.accountService.Account(ctx, account.Query{ID: c.DebtorAccountID.String()}, c.OrgID)
		if err != nil {
			return err
		}
		c.DebtorAccount = acc
	}

	if c.DebtorAccount != nil && c.DebtorAccount.SubType == account.SubTypeJointSimple {
		if err := s.updateConsentStatus(ctx, c, ConsentStatusPartiallyAccepted); err != nil {
			return err
		}
		s.scheduleConsent(ctx, c, timeutil.DateTimeNow().Add(scheduleDelay))
		return nil
	}
	return s.updateConsentStatus(ctx, c, ConsentStatusAuthorized)
}

func (s Service) Consent(ctx context.Context, id, orgID string) (*Consent, error) {
	id = strings.TrimPrefix(id, ConsentURNPrefix)
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

func (s Service) EnrollConsent(ctx context.Context, id, orgID string, opts EnrollmentOptions) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	if c.Status != ConsentStatusAwaitingAuthorization {
		return errorutil.Format("%w: payment consent is not in awaiting authorization status", ErrInvalidConsentStatus)
	}

	if c.UserIdentification != opts.UserIdentification {
		return errorutil.New("payment consent user identification mismatch")
	}

	if !reflect.DeepEqual(c.BusinessIdentification, opts.BusinessIdentification) {
		return errorutil.New("payment consent business identification mismatch")
	}

	if c.EnrollmentID != nil {
		return errorutil.New("payment consent already has an enrollment")
	}

	c.EnrollmentID = &opts.EnrollmentID
	c.DebtorAccountID = opts.DebtorAccountID
	c.EnrollmentChallenge = &opts.Challenge
	c.EnrollmentTransactionLimit = &opts.TransactionLimit
	c.EnrollmentDailyLimit = &opts.DailyLimit
	return s.updateConsent(ctx, c)
}

func (s Service) RejectConsentByID(ctx context.Context, id, orgID string, code ConsentRejectionReasonCode, detail string) (*Consent, error) {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}
	return c, s.RejectConsent(ctx, c, code, detail)
}

func (s Service) RejectConsent(ctx context.Context, c *Consent, code ConsentRejectionReasonCode, detail string) error {
	if c.Status == ConsentStatusRejected {
		return ErrConsentAlreadyRejected
	}

	c.Rejection = &ConsentRejection{Code: code, Detail: detail}
	if err := s.updateConsentStatus(ctx, c, ConsentStatusRejected); err != nil {
		return err
	}
	s.unscheduleConsent(ctx, c)
	s.notifyConsentStatusChange(ctx, c)
	return nil
}

func (s Service) CreatePayments(ctx context.Context, payments []*Payment) error {

	firstPayment := payments[0]
	consentID := firstPayment.ConsentID
	if consentID == uuid.Nil {
		return errorutil.Format("%w: could not infer consent id", ErrMissingValue)
	}

	orgID := firstPayment.OrgID
	c, err := s.Consent(ctx, consentID.String(), orgID)
	if err != nil {
		return err
	}

	if c.Status == ConsentStatusPartiallyAccepted {
		return ErrConsentPartiallyAccepted
	}

	if c.Status != ConsentStatusAuthorized {
		return errorutil.Format("%w: payment consent is not in authorized status", ErrInvalidConsentStatus)
	}

	if err := s.consumeConsent(ctx, c); err != nil {
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
	if err := s.db.Create(&payments).Error; err != nil {
		return fmt.Errorf("could not create payments: %w", err)
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

	if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != p.ClientID {
		return nil, ErrClientNotAllowed
	}

	if err := s.runPostCreationAutomations(ctx, p); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) Payments(ctx context.Context, orgID string, filter *Filter) ([]*Payment, error) {
	payments, err := s.payments(ctx, orgID, filter)
	if err != nil {
		return nil, err
	}

	for _, p := range payments {
		if err := s.runPostCreationAutomations(ctx, p); err != nil {
			return nil, err
		}
	}
	return payments, nil
}

func (s Service) Cancel(ctx context.Context, id, orgID string, doc consent.Document) (*Payment, error) {
	p, err := s.Payment(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	c, err := s.Consent(ctx, p.ConsentID.String(), orgID)
	if err != nil {
		return nil, err
	}

	if doc.Rel != consent.RelationCPF {
		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
	}

	if c.UserIdentification != doc.Identification {
		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
	}

	if err := s.cancel(ctx, p, CancelledFromInitiator, c.UserIdentification); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) CancelAll(ctx context.Context, consentID, orgID string, doc consent.Document) ([]*Payment, error) {
	c, err := s.Consent(ctx, consentID, orgID)
	if err != nil {
		return nil, err
	}

	if doc.Rel != consent.RelationCPF {
		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
	}

	if c.UserIdentification != doc.Identification {
		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
	}

	payments, err := s.payments(ctx, orgID, &Filter{ConsentID: c.ID.String()})
	if err != nil {
		return nil, err
	}

	var cancelled []*Payment
	var cancelErrs error
	for _, p := range payments {
		if err := s.cancel(ctx, p, CancelledFromInitiator, c.UserIdentification); err != nil {
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

func (s Service) validateConsent(_ context.Context, c *Consent, debtorAccount *Account) error {
	if debtorAccount != nil && c.CreditorAccountISBP == debtorAccount.ISPB && c.CreditorAccountNumber == debtorAccount.Number {
		return ErrCreditorAndDebtorAccountsAreEqual
	}

	if c.PaymentDate != nil && c.PaymentDate.Before(timeutil.BrazilDateNow()) {
		return errorutil.Format("%w: payment date must be in the future", ErrInvalidDate)
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

		if startDate.Before(today) {
			return errorutil.Format("%w: schedule cannot start in the past", ErrInvalidDate)
		}
		if lastPaymentDate.After(twoYearsLater) {
			return errorutil.Format("%w: schedule cannot end more than 2 years from now", ErrInvalidDate)
		}

	}

	if c.PaymentSchedule != nil && c.PaymentSchedule.Single == nil && !slices.Contains([]LocalInstrument{
		LocalInstrumentMANU,
		LocalInstrumentDICT,
		LocalInstrumentQRES,
	}, c.LocalInstrument) {
		return errorutil.Format("%w: only MANU, DICT or QRES are allowed when using schedule other than single", ErrInvalidPayment)
	}

	if c.LocalInstrument == LocalInstrumentMANU && c.Proxy != nil {
		return errorutil.Format("%w: proxy must not be set when using local instrument MANU", ErrInvalidPayment)
	}

	if c.LocalInstrument == LocalInstrumentDICT && c.QRCode != nil {
		return errorutil.Format("%w: qr code is not allowed when using local instrument DICT", ErrInvalidPayment)
	}

	if slices.Contains([]LocalInstrument{
		LocalInstrumentINIC,
		LocalInstrumentDICT,
		LocalInstrumentQRDN,
		LocalInstrumentQRES,
	}, c.LocalInstrument) && c.Proxy == nil {
		return errorutil.Format("%w: proxy must be set when using localInstrument INIC, DICT, QRDN or QRES", ErrInvalidPayment)
	}

	if slices.Contains([]AccountType{
		AccountTypeCACC,
		AccountTypeSVGS,
	}, c.CreditorAccountType) && c.CreditorAccountIssuer == nil {
		return errorutil.Format("%w: creditor account issuer is required for account types CACC or SVGS", ErrInvalidPayment)
	}

	if debtorAccount != nil && slices.Contains([]AccountType{
		AccountTypeCACC,
		AccountTypeSVGS,
	}, debtorAccount.Type) && debtorAccount.Issuer == nil {
		return errorutil.New("debtor account issuer is required for account types CACC or SVGS")
	}

	if c.PaymentCurrency != "BRL" {
		return errorutil.Format("%w: payment currency must be BRL", ErrInvalidData)
	}

	return nil
}

func (s Service) runConsentPreCreationAutomations(ctx context.Context, c *Consent) error {
	switch c.PaymentAmount {
	case "10422.00":
		return ErrInvalidPayment
	}

	s.scheduleConsent(ctx, c, timeutil.DateTimeNow().Add(scheduleDelay))
	return nil
}

func (s Service) runConsentPostCreationAutomations(ctx context.Context, c *Consent) error {
	slog.DebugContext(ctx, "evaluating payment consent automations", "status", c.Status, "amount", c.PaymentAmount)

	now := timeutil.DateTimeNow()
	if now.Before(c.UpdatedAt.Add(5 * time.Second)) {
		slog.DebugContext(ctx, "payment consent was updated less than 5 secs ago, skipping transitions", "updated_at", c.UpdatedAt.String())
		return nil
	}

	switch c.Status {
	case ConsentStatusAwaitingAuthorization:
		if timeutil.DateTimeNow().After(c.ExpiresAt) {
			slog.DebugContext(ctx, "payment consent awaiting authorization for too long, moving to rejected")
			return s.RejectConsent(ctx, c, ConsentRejectionAuthorizationTimeout, "consent awaiting authorization for too long")
		}

		switch c.PaymentAmount {
		case "300.01":
			return s.RejectConsent(ctx, c, ConsentRejectionInvalidAmount, "forced rejection")
		case "300.02":
			return s.RejectConsent(ctx, c, ConsentRejectionNotProvided, "forced rejection")
		case "300.03":
			return s.RejectConsent(ctx, c, ConsentRejectionInfrastructureFailure, "forced rejection")
		case "300.04":
			return s.RejectConsent(ctx, c, ConsentRejectionConsumptionTimeout, "forced rejection")
		case "300.05":
			return s.RejectConsent(ctx, c, ConsentRejectionAccountDoesNotAllowPayment, "forced rejection")
		case "300.06":
			return s.RejectConsent(ctx, c, ConsentRejectionInsufficientFunds, "forced rejection")
		case "300.07":
			return s.RejectConsent(ctx, c, ConsentRejectionAmountAboveLimit, "forced rejection")
		case "300.08":
			return s.RejectConsent(ctx, c, ConsentRejectionInvalidQRCode, "forced rejection")
		}
	case ConsentStatusPartiallyAccepted:
		if timeutil.DateTimeNow().After(c.StatusUpdatedAt.Add(3 * time.Minute)) {
			slog.DebugContext(ctx, "payment consent partially accepted for more than 3 minutes, moving to authorized")
			if err := s.updateConsentStatus(ctx, c, ConsentStatusAuthorized); err != nil {
				return err
			}
			s.unscheduleConsent(ctx, c)
			s.notifyConsentStatusChange(ctx, c)
			return nil
		}
	case ConsentStatusAuthorized:
		if timeutil.DateTimeNow().After(c.ExpiresAt) {
			slog.DebugContext(ctx, "payment consent reached expiration, moving to rejected")
			return s.RejectConsent(ctx, c, ConsentRejectionConsumptionTimeout, "payment consent authorization reached expiration")
		}
		return nil
	}

	return nil
}

func (s Service) consumeConsent(ctx context.Context, c *Consent) error {
	if err := s.updateConsentStatus(ctx, c, ConsentStatusConsumed); err != nil {
		return err
	}

	s.unscheduleConsent(ctx, c)
	s.notifyConsentStatusChange(ctx, c)
	return nil
}

func (s Service) updateConsentStatus(ctx context.Context, c *Consent, status ConsentStatus) error {
	oldStatus := c.Status
	slog.DebugContext(ctx, "updating payment consent status", "current_status", oldStatus, "new_status", status)

	c.Status = status
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	if err := s.updateConsent(ctx, c); err != nil {
		return fmt.Errorf("could not update payment consent status: %w", err)
	}
	return nil
}

func (s Service) updateConsent(ctx context.Context, c *Consent) error {
	c.UpdatedAt = timeutil.DateTimeNow()
	return s.db.WithContext(ctx).
		Model(&Consent{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", c.ID, c.OrgID).
		Updates(c).Error
}

func (s Service) notifyConsentStatusChange(ctx context.Context, c *Consent) {
	slog.DebugContext(ctx, "notifying client about payment consent status change", "status", c.Status)
	s.webhookService.Notify(ctx, c.ClientID, "/payments/"+s.version+"/consents/"+c.URN())
}

func (s Service) scheduleConsent(ctx context.Context, c *Consent, nextRunAt timeutil.DateTime) {
	s.scheduleService.Schedule(ctx, &schedule.Schedule{
		ID:        c.ID,
		OrgID:     c.OrgID,
		TaskType:  schedule.TaskTypePaymentConsent,
		NextRunAt: nextRunAt,
	})
}

func (s Service) unscheduleConsent(ctx context.Context, c *Consent) {
	s.scheduleService.Unschedule(ctx, c.ID.String(), c.OrgID)
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

		if !reflect.DeepEqual(p.EnrollmentID, c.EnrollmentID) {
			return errorutil.Format("%w: payment enrollment id doesn't match the consent", ErrPaymentDoesNotMatchConsent)
		}

		if p.EnrollmentID != nil && (p.AuthorisationFlow == nil || *p.AuthorisationFlow != AuthorisationFlowFIDOFlow) {
			return errorutil.New("payment enrollment id is set but authorisation flow is not FIDO")
		}

		if p.EndToEndID == "" {
			return errorutil.Format("%w: end to end id is required", ErrMissingValue)
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

		if slices.Contains([]LocalInstrument{
			LocalInstrumentMANU,
			LocalInstrumentDICT,
		}, p.LocalInstrument) && p.TransactionIdentification != nil {
			return errorutil.New("invalid consent: transaction identification is not allowed if local instrument is MANU or DICT")
		}
	}

	return nil
}

func (s Service) runPreCreationAutomations(ctx context.Context, p *Payment) error {
	switch p.Amount {
	case "10422.00":
		return ErrInvalidPayment
	}

	s.schedule(ctx, p, timeutil.DateTimeNow().Add(scheduleDelay))
	return nil
}

func (s Service) runPostCreationAutomations(ctx context.Context, p *Payment) error {
	slog.DebugContext(ctx, "evaluating payment automations", "status", p.Status, "amount", p.Amount)

	now := timeutil.DateTimeNow()
	if now.Before(p.UpdatedAt.Add(5 * time.Second)) {
		slog.DebugContext(ctx, "payment was updated less than 5 secs ago, skipping transitions", "updated_at", p.UpdatedAt.String())
		return nil
	}

	c, err := s.Consent(ctx, p.ConsentID.String(), p.OrgID)
	if err != nil {
		return err
	}

	switch p.Status {
	case StatusRCVD:
		if p.LocalInstrument != c.LocalInstrument {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "local instrument does not match the value specified in the consent")
		}

		if p.LocalInstrument == LocalInstrumentQRES && p.TransactionIdentification != nil {
			return s.reject(ctx, p, RejectionInvalidPaymentDetail, "transaction identification is not allowed when using local instrument QRES")
		}

		if p.Amount != c.PaymentAmount {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "amount does not match the value specified in the consent")
		}

		if p.Currency != c.PaymentCurrency {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "currency does not match the value specified in the consent")
		}

		if p.CreditorAccountISBP != c.CreditorAccountISBP {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor account isbp does not match the value specified in the consent")
		}

		if !reflect.DeepEqual(p.CreditorAccountIssuer, c.CreditorAccountIssuer) {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor account issuer does not match the value specified in the consent")
		}

		if p.CreditorAccountNumber != c.CreditorAccountNumber {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor account number does not match the value specified in the consent")
		}

		if p.CreditorAccountType != c.CreditorAccountType {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor account type does not match the value specified in the consent")
		}

		if !reflect.DeepEqual(p.QRCode, c.QRCode) {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "qr code does not match the value specified in the consent")
		}

		if !reflect.DeepEqual(p.Proxy, c.Proxy) {
			return s.reject(ctx, p, RejectionPaymentConsentMismatch, "proxy does not match the value specified in the consent")
		}

		if c.EnrollmentTransactionLimit != nil && ConvertAmount(p.Amount) > ConvertAmount(*c.EnrollmentTransactionLimit) {
			return s.reject(ctx, p, RejectionExceedsLimit, "payment amount is greater than the configured transaction limit in the consent")
		}

		if c.EnrollmentDailyLimit != nil {
			today := timeutil.BrazilDateNow()
			payments, err := s.payments(ctx, c.OrgID, &Filter{
				EnrollmentID: p.EnrollmentID.String(),
				Statuses:     []Status{StatusACSC, StatusSCHD},
				From:         &today,
				To:           &today,
			})
			if err != nil {
				return err
			}
			if ConvertAmount(p.Amount)+SumPayments(payments) > ConvertAmount(*c.EnrollmentDailyLimit) {
				return s.reject(ctx, p, RejectionExceedsLimit, "payment amount goes beyond the configured daily limit in the consent")
			}
		}

		if err := s.updateStatus(ctx, p, StatusACCP); err != nil {
			return err
		}
		s.schedule(ctx, p, now.Add(scheduleDelay))
		return nil

	case StatusACCP:
		today := timeutil.BrazilDateNow()
		if p.Date.After(today) {
			if err := s.updateStatus(ctx, p, StatusSCHD); err != nil {
				return err
			}
			s.schedule(ctx, p, p.Date.DateTime())
			s.notifyStatusChange(ctx, p)
			return nil
		}

		if err := s.updateStatus(ctx, p, StatusACPD); err != nil {
			return err
		}
		s.schedule(ctx, p, now.Add(scheduleDelay))
		return nil

	case StatusSCHD:
		today := timeutil.BrazilDateNow()
		if p.Date.After(today) {
			return nil
		}

		if err := s.updateStatus(ctx, p, StatusACPD); err != nil {
			return err
		}
		s.schedule(ctx, p, now.Add(scheduleDelay))
		return nil

	case StatusACPD:
		if err := s.updateStatus(ctx, p, StatusACSC); err != nil {
			return err
		}
		s.unschedule(ctx, p)
		s.notifyStatusChange(ctx, p)
		return nil
	default:
		return nil
	}
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
	if err := s.updateStatus(ctx, p, StatusCANC); err != nil {
		return err
	}

	s.unschedule(ctx, p)
	s.notifyStatusChange(ctx, p)
	return nil
}

func (s Service) reject(ctx context.Context, p *Payment, code RejectionReasonCode, detail string) error {
	p.Rejection = &Rejection{Code: code, Detail: detail}
	if err := s.updateStatus(ctx, p, StatusRJCT); err != nil {
		return err
	}

	s.unschedule(ctx, p)
	s.notifyStatusChange(ctx, p)
	return nil
}

func (s Service) updateStatus(ctx context.Context, p *Payment, status Status) error {
	slog.DebugContext(ctx, "updating payment status", "current_status", p.Status, "new_status", status)

	p.Status = status
	p.StatusUpdatedAt = timeutil.DateTimeNow()
	return s.update(ctx, p)
}

func (s Service) update(ctx context.Context, p *Payment) error {
	p.UpdatedAt = timeutil.DateTimeNow()
	return s.db.WithContext(ctx).
		Model(&Payment{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", p.ID, p.OrgID).
		Updates(p).Error
}

func (s Service) payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error) {
	if opts == nil {
		opts = &Filter{}
	}

	query := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if opts.ConsentID != "" {
		query = query.Where("consent_id = ?", strings.TrimPrefix(opts.ConsentID, ConsentURNPrefix))
	}
	if opts.EnrollmentID != "" {
		query = query.Where("enrollment_id = ?", opts.EnrollmentID)
	}
	if opts.Statuses != nil {
		query = query.Where("status IN ?", opts.Statuses)
	}
	if opts.From != nil {
		query = query.Where("date >= ?", opts.From)
	}
	if opts.To != nil {
		query = query.Where("date <= ?", opts.To)
	}

	var payments []*Payment
	if err := query.Find(&payments).Error; err != nil {
		return nil, fmt.Errorf("could not find payments: %w", err)
	}

	return payments, nil
}

func (s Service) schedule(ctx context.Context, p *Payment, nextRunAt timeutil.DateTime) {
	s.scheduleService.Schedule(ctx, &schedule.Schedule{
		ID:        p.ID,
		OrgID:     p.OrgID,
		TaskType:  schedule.TaskTypePayment,
		NextRunAt: nextRunAt,
	})
}

func (s Service) unschedule(ctx context.Context, p *Payment) {
	s.scheduleService.Unschedule(ctx, p.ID.String(), p.OrgID)
}

func (s Service) notifyStatusChange(ctx context.Context, p *Payment) {
	slog.DebugContext(ctx, "notifying client about payment status change", "status", p.Status)
	s.webhookService.Notify(ctx, p.ClientID, "/payments/"+s.version+"/pix/payments/"+p.ID.String())
}
