package autopayment

import (
	"context"
	"errors"
	"fmt"
	"github.com/luikyv/mock-bank/internal/bank"
	"github.com/luikyv/mock-bank/internal/webhook"
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
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"gorm.io/gorm"
)

type Service struct {
	db             *gorm.DB
	userService    user.Service
	accountService account.Service
	webhookService webhook.Service
}

func NewService(db *gorm.DB, userService user.Service, accountService account.Service, webhookService webhook.Service) Service {
	return Service{db: db, userService: userService, accountService: accountService, webhookService: webhookService}
}

func (s Service) WithTx(tx *gorm.DB) Service {
	return NewService(tx, s.userService, s.accountService, s.webhookService)
}

func (s Service) CreateConsent(ctx context.Context, c *Consent, debtorAcc *payment.Account) error {
	c.Status = ConsentStatusAwaitingAuthorization
	if sweeping := c.Configuration.Sweeping; sweeping != nil && sweeping.StartDateTime == nil {
		now := timeutil.DateTimeNow()
		sweeping.StartDateTime = &now
	}

	if err := s.validateConsent(ctx, c, debtorAcc); err != nil {
		return err
	}

	u, err := s.userService.User(ctx, user.Query{CPF: c.UserIdentification}, c.OrgID)
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

	acc, err := s.accountService.Account(ctx, account.Query{Number: debtorAcc.Number}, c.OrgID)
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

	if c.Status != ConsentStatusAwaitingAuthorization {
		return errorutil.New("consent is not awaiting authorization")
	}

	now := timeutil.DateTimeNow()
	c.AuthorizedAt = &now
	return s.updateConsentStatus(ctx, c, ConsentStatusAuthorized)
}

func (s Service) Consent(ctx context.Context, id, orgID string) (*Consent, error) {
	c, err := s.consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if err := s.runConsentPostCreationAutomations(ctx, c); err != nil {
		return nil, err
	}

	return c, nil
}

func (s Service) consent(ctx context.Context, id, orgID string) (*Consent, error) {
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

	return c, nil
}

func (s Service) RejectConsentByID(ctx context.Context, id, orgID string, rejection ConsentRejection) (*Consent, error) {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
	}

	return c, s.RejectConsent(ctx, c, rejection)
}

func (s Service) RejectConsent(ctx context.Context, c *Consent, rejection ConsentRejection) error {
	if !slices.Contains([]ConsentStatus{
		ConsentStatusAwaitingAuthorization,
		ConsentStatusPartiallyAccepted,
	}, c.Status) {
		return ErrCannotRejectConsent
	}

	c.Rejection = &rejection
	return s.updateConsentStatus(ctx, c, ConsentStatusRejected)
}

func (s Service) RevokeConsent(ctx context.Context, id, orgID string, revocation ConsentRevocation) (*Consent, error) {
	var revoked *Consent
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txService := s.WithTx(tx)
		c, err := txService.Consent(ctx, id, orgID)
		if err != nil {
			return err
		}

		if err := txService.revokeConsent(ctx, c, revocation); err != nil {
			return err
		}

		payments, err := txService.Payments(ctx, orgID, &Filter{ConsentID: id})
		if err != nil {
			return err
		}
		for _, p := range payments {
			if err := txService.reject(ctx, p, RejectionRevokedConsent, "the consent was revoked"); err != nil {
				if errors.Is(err, ErrRejectionNotAllowed) {
					continue
				}
				return err
			}
		}

		revoked = c
		return nil
	})

	return revoked, err
}

func (s Service) EditConsent(ctx context.Context, id, orgID string, edition ConsentEdition) (*Consent, error) {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if err := s.validateConsentEdition(ctx, c, edition); err != nil {
		return nil, err
	}

	c.RiskSignals = edition.RiskSignals
	for i := range c.Creditors {
		c.Creditors[i].Name = edition.Creditors[0].Name
	}
	c.ExpiresAt = edition.ExpiresAt
	var maxAmount *string
	if edition.RecurringConfiguration != nil && edition.RecurringConfiguration.Automatic != nil {
		maxAmount = edition.RecurringConfiguration.Automatic.MaximumVariableAmount
	}
	c.Configuration.Automatic.MaximumVariableAmount = maxAmount

	return c, s.saveConsent(ctx, c)
}

func (s Service) Create(ctx context.Context, p *Payment) error {

	if p.ConsentID == uuid.Nil {
		return errorutil.New("could not infer consent id")
	}

	c, err := s.Consent(ctx, p.ConsentID.String(), p.OrgID)
	if err != nil {
		return err
	}

	if c.Status != ConsentStatusAuthorized {
		return ErrConsentNotAuthorized
	}

	if err := s.validate(ctx, c, p); err != nil {
		return err
	}

	p.Status = payment.StatusRCVD
	p.DebtorAccountID = c.DebtorAccountID
	p.DebtorAccount = c.DebtorAccount
	date, _ := payment.ParseEndToEndDate(p.EndToEndID)
	p.Date = date.BrazilDate()

	if err := s.runPreCreationAutomations(ctx, p); err != nil {
		return err
	}
	return s.db.Create(p).Error
}

func (s Service) Payment(ctx context.Context, id, orgID string) (*Payment, error) {
	p, err := s.payment(ctx, Query{ID: id, DebtorAccount: true}, orgID)
	if err != nil {
		return nil, err
	}

	return p, s.runPostCreationAutomations(ctx, p)
}

func (s Service) Payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error) {
	payments, err := s.payments(ctx, orgID, opts)
	if err != nil {
		return nil, err
	}
	for _, p := range payments {
		if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != p.ClientID {
			return nil, ErrClientNotAllowed
		}

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

	if doc.Rel != c.UserRel {
		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
	}

	if doc.Identification != c.UserIdentification {
		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
	}

	if err := s.cancel(ctx, p, payment.CancelledFromInitiator, c.UserIdentification); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) cancel(ctx context.Context, p *Payment, from payment.CancelledFrom, by string) error {
	if !slices.Contains([]payment.Status{payment.StatusPDNG, payment.StatusSCHD}, p.Status) {
		return errorutil.Format("%w: payment with status %s cannot be cancelled, only payments with status PDNG or SCHD can be cancelled", ErrCancelNotAllowed, p.Status)
	}

	if p.Status == payment.StatusSCHD && !timeutil.BrazilDateNow().Before(p.Date) {
		return errorutil.Format("%w: scheduled payments can only be cancelled until 23:59 (BRT) of the day before the payment date (%s)", ErrCancelNotAllowed, p.Date.String())
	}

	reason := payment.CancellationReasonPending
	if p.Status == payment.StatusSCHD {
		reason = payment.CancellationReasonScheduled
	}
	p.Cancellation = &payment.Cancellation{
		At:     timeutil.DateTimeNow(),
		Reason: reason,
		From:   from,
		By:     by,
	}
	return s.updateStatus(ctx, p, payment.StatusCANC)
}

func (s Service) createConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Create(c).Error
}

func (s Service) validateConsent(_ context.Context, c *Consent, debtorAccount *payment.Account) error {
	if c.UserRel != consent.RelationCPF {
		return errorutil.Format("%w: only CPF is allowed for logged user document relation", ErrInvalidPayment)
	}

	if c.BusinessRel != nil && *c.BusinessRel != consent.RelationCNPJ {
		return errorutil.Format("%w: only CNPJ is allowed for business document relation", ErrInvalidPayment)
	}

	if automatic := c.Configuration.Automatic; automatic != nil {
		today := timeutil.BrazilDateNow()
		if automatic.ReferenceStartDate.Before(today) {
			return errorutil.Format("%w: reference start date cannot be in the past", ErrInvalidPayment)
		}

		if len(c.Creditors) != 1 {
			return errorutil.Format("%w: only one creditor is allowed for automatic pix", ErrInvalidPayment)
		}

		if c.Creditors[0].Type == payment.CreditorTypeIndividual {
			return errorutil.Format("%w: only creditor of type PESSOA_JURIDICA is allowed for automatic pix", ErrInvalidPayment)
		}

		if exp := c.ExpiresAt; exp != nil {
			now := timeutil.DateTimeNow()
			if c.ExpiresAt.Before(now) {
				return errorutil.Format("%w: expiration cannot be in the past", ErrInvalidPayment)
			}

			if exp.Hour() != 23 || exp.Minute() != 59 || exp.Second() != 59 {
				return errorutil.Format("%w: expiration time for automatic pix must be at 23:59:59 (UTC)", ErrInvalidPayment)
			}
		}

		if automatic.FixedAmount != nil && automatic.MaximumVariableAmount != nil {
			return errorutil.Format("%w: at most one of fixed amount and maximum variable amount can be informed", ErrInvalidPayment)
		}

		if automatic.FixedAmount != nil && automatic.MinimumVariableAmount != nil {
			return errorutil.Format("%w: mininum variable amount cannot be informed if fixed amount is present", ErrInvalidPayment)
		}

		if automatic.MaximumVariableAmount != nil && automatic.MinimumVariableAmount != nil && convertAmount(*automatic.MinimumVariableAmount) > convertAmount(*automatic.MaximumVariableAmount) {
			return errorutil.Format("%w: maximum variable amount cannot be lower than minimum variable amount", ErrInvalidPayment)
		}

		if firstPayment := automatic.FirstPayment; firstPayment != nil {
			if firstPayment.Currency != "BRL" {
				return errorutil.Format("%w: only BRL currency is allowed", ErrInvalidDate)
			}

			if slices.Contains([]payment.AccountType{
				payment.AccountTypeCACC,
				payment.AccountTypeSVGS,
			}, firstPayment.CreditorAccount.Type) && firstPayment.CreditorAccount.Issuer == nil {
				return errorutil.New("first payment creditor account issuer is required for account types CACC or SVGS")
			}

			if firstPayment.Date.Before(today) {
				return errorutil.Format("%w: first payment date cannot be in the past", ErrInvalidDate)
			}
		}
	}

	if sweeping := c.Configuration.Sweeping; sweeping != nil {
		if businessCNPJ := c.BusinessIdentification; businessCNPJ != nil {
			baseRootCNPJ := (*businessCNPJ)[:8]
			for _, creditor := range c.Creditors {
				if creditor.Type != payment.CreditorTypeCompany {
					return errorutil.Format("%w: sweeping requires all creditors to be companies when the user is PESSOA_JURIDICA", ErrInvalidPayment)
				}

				if !strings.HasPrefix(creditor.CPFCNPJ, baseRootCNPJ) {
					return errorutil.Format("%w: sweeping requires all creditor CNPJs to share the same root as the user's business CNPJ", ErrInvalidPayment)
				}
			}
		} else {
			if len(c.Creditors) != 1 {
				return errorutil.Format("%w: sweeping requires exactly one creditor when the user is PESSOA_NATURAL", ErrInvalidPayment)
			}

			creditor := c.Creditors[0]
			if creditor.Type != payment.CreditorTypeIndividual {
				return errorutil.Format("%w: sweeping requires the creditor to be of type PESSOA_NATURAL when the user is a person", ErrInvalidPayment)
			}

			if creditor.CPFCNPJ != c.UserIdentification {
				return errorutil.Format("%w: sweeping requires the creditor's CPF to match the logged user's CPF", ErrInvalidPayment)
			}
		}

		// Check if start date is after expiration date with leeway of 5 seconds.
		if sweeping.StartDateTime != nil && c.ExpiresAt != nil && sweeping.StartDateTime.After(c.ExpiresAt.Add(-5*time.Second).Time) {
			return errorutil.Format("%w: sweeping start date cannot be after expiration date", ErrInvalidData)
		}
	}

	if debtorAccount != nil && slices.Contains([]payment.AccountType{
		payment.AccountTypeCACC,
		payment.AccountTypeSVGS,
	}, debtorAccount.Type) && debtorAccount.Issuer == nil {
		return errorutil.New("debtor account issuer is required for account types CACC or SVGS")
	}

	return nil
}

func (s Service) validateConsentEdition(_ context.Context, c *Consent, edition ConsentEdition) error {
	if c.Status != ConsentStatusAuthorized {
		return errorutil.New("consent is not authorized")
	}

	if c.Status != ConsentStatusAuthorized {
		return ErrConsentNotAuthorized
	}

	if c.Configuration.Automatic == nil {
		return errorutil.Format("%w: edition is only allowed for automatic pix", ErrFieldNotAllowed)
	}

	if edition.LoggedUser.Identification != c.UserIdentification {
		return errorutil.Format("%w: logged user identification doesn't match the consent", ErrInvalidEdition)
	}

	if edition.RiskSignals == nil {
		return errorutil.Format("%w: edition risk signals are required for automatic pix edition", ErrInvalidEdition)
	}

	if len(edition.Creditors) != 1 {
		return errorutil.New("only one creditor is allowed for automatic pix edition")
	}

	if edition.ExpiresAt != nil && edition.ExpiresAt.Before(timeutil.DateTimeNow()) {
		return errorutil.Format("%w: edition expiration cannot be in the past", ErrInvalidEdition)
	}

	if c.Configuration.Automatic.FixedAmount != nil &&
		edition.RecurringConfiguration != nil &&
		edition.RecurringConfiguration.Automatic != nil &&
		edition.RecurringConfiguration.Automatic.MaximumVariableAmount != nil {
		return errorutil.Format("%w: maximum variable amount is not allowed for fixed amount consents", ErrInvalidEdition)
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
	return nil
}

func (s Service) runConsentPostCreationAutomations(ctx context.Context, c *Consent) error {
	switch c.Status {
	case ConsentStatusAwaitingAuthorization:
		if timeutil.DateTimeNow().After(c.CreatedAt.Add(60 * time.Minute).Time) {
			slog.DebugContext(ctx, "recurring consent awaiting authorization for too long, moving to rejected")
			return s.RejectConsent(ctx, c, ConsentRejection{
				By:     TerminatedByHolder,
				From:   TerminatedFromHolder,
				Code:   ConsentRejectionAuthorizationTimeout,
				Detail: "consent awaiting authorization for too long",
			})
		}
	case ConsentStatusAuthorized:
		if c.ExpiresAt != nil && timeutil.DateTimeNow().After(c.ExpiresAt.Time) {
			slog.DebugContext(ctx, "recurring consent is authorized, but expired, moving to consumed")
			return s.updateConsentStatus(ctx, c, ConsentStatusConsumed)
		}

		if sweeping := c.Configuration.Sweeping; sweeping != nil {
			if totalAllowedAmount := sweeping.TotalAllowedAmount; totalAllowedAmount != nil {
				_, currentTotalAmount, err := s.currentAmount(ctx, c, nil, nil)
				if err != nil {
					return err
				}
				if currentTotalAmount > convertAmount(*totalAllowedAmount) {
					return s.updateConsentStatus(ctx, c, ConsentStatusConsumed)
				}
			}
		}
	}

	return nil
}

func (s Service) revokeConsent(ctx context.Context, c *Consent, revocation ConsentRevocation) error {
	if c.Status != ConsentStatusAuthorized {
		return ErrConsentNotAuthorized
	}

	c.Revocation = &revocation
	return s.updateConsentStatus(ctx, c, ConsentStatusRevoked)
}

func (s Service) saveConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Save(c).Error
}

func (s Service) validate(_ context.Context, c *Consent, p *Payment) error {
	if sweeping := c.Configuration.Sweeping; sweeping != nil {
		if p.RiskSignals == nil {
			return errorutil.New("risk signals is required for sweeping payments")
		}

		if sweeping.StartDateTime != nil && p.Date.Before(sweeping.StartDateTime.BrazilDate()) {
			return errorutil.Format("%w: payment date cannot be after sweeping start date", ErrPaymentDoesNotMatchConsent)
		}
	}

	if c.Configuration.Automatic != nil {
		if p.LocalInstrument != payment.LocalInstrumentMANU {
			return errorutil.New("local instrument must be MANU for automatic payments")
		}

		if p.Reference == nil {
			return errorutil.Format("%w: payment reference is required for automatic payments", ErrInvalidPayment)
		}
	}

	endToEndDate, err := payment.ParseEndToEndDate(p.EndToEndID)
	if err != nil {
		return errorutil.Format("%w: invalid end to end id date: %w", ErrInvalidEndToEndID, err)
	}

	if p.Date != endToEndDate.BrazilDate() {
		return errorutil.Format("%w: end to end id date doesn't match the payment date", ErrInvalidEndToEndID)
	}

	if slices.Contains([]payment.AccountType{
		payment.AccountTypeCACC,
		payment.AccountTypeSVGS,
	}, p.CreditorAccountType) && p.CreditorAccountIssuer == nil {
		return errorutil.New("creditor account issuer is required for account types CACC or SVGS")
	}

	if p.LocalInstrument == payment.LocalInstrumentMANU && p.Proxy != nil {
		return errorutil.New("proxy must not be set when using local instrument MANU")
	}

	if slices.Contains([]payment.LocalInstrument{
		payment.LocalInstrumentMANU,
		payment.LocalInstrumentDICT,
	}, p.LocalInstrument) && p.TransactionIdentification != nil {
		return errorutil.New("transaction identification is not allowed if local instrument is MANU or DICT")
	}

	if p.LocalInstrument == payment.LocalInstrumentINIC && p.TransactionIdentification == nil {
		return errorutil.New("transaction identification must be informed if local instrument is INIC")
	}

	creditorFound := false
	for _, creditor := range c.Creditors {
		if creditor.CPFCNPJ == p.DocumentIdentification {
			creditorFound = true
		}
	}
	if !creditorFound {
		return errorutil.Format("%w: document doesn't match any creditor", ErrPaymentDoesNotMatchConsent)
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
	now := timeutil.DateTimeNow()
	if now.Before(p.UpdatedAt.Add(5 * time.Second)) {
		slog.DebugContext(ctx, "payment was updated less than 5 secs ago, skipping transitions", "updated_at", p.UpdatedAt.String())
		return nil
	}

	slog.DebugContext(ctx, "evaluating payment automations", "id", p.ID, "status", p.Status, "amount", p.Amount)

	c, err := s.Consent(ctx, p.ConsentID.String(), p.OrgID)
	if err != nil {
		return err
	}

	switch p.Status {
	case payment.StatusRCVD:
		if c.ExpiresAt != nil && p.Date.After(c.ExpiresAt.BrazilDate()) {
			return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be received after the consent expiration date")
		}

		if automatic := c.Configuration.Automatic; automatic != nil {

			if firstPaymentConfig := automatic.FirstPayment; firstPaymentConfig != nil {
				firstPayment, err := s.payment(ctx, Query{ConsentID: c.ID.String(), Order: "created_at ASC"}, c.OrgID)
				if err != nil {
					return err
				}
				if p.ID == firstPayment.ID {
					if !p.Date.Equal(firstPaymentConfig.Date) {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment date does not match the configured first payment date in the consent")
					}

					if p.Amount != firstPaymentConfig.Amount {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment amount does not match the configured first payment amount in the consent")
					}

					if p.Currency != firstPaymentConfig.Currency {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment currency does not match the configured first payment currency in the consent")
					}

					if p.CreditorAccountISBP != firstPaymentConfig.CreditorAccount.ISPB {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account isbp does not match the configured first payment creditor account isbp in the consent")
					}

					if p.CreditorAccountType != firstPaymentConfig.CreditorAccount.Type {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account type does not match the configured first payment creditor account type in the consent")
					}

					if !reflect.DeepEqual(p.CreditorAccountIssuer, firstPaymentConfig.CreditorAccount.Issuer) {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account issuer does not match the configured first payment creditor account issuer in the consent")
					}

					if p.CreditorAccountNumber != firstPaymentConfig.CreditorAccount.Number {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account number does not match the configured first payment creditor account number in the consent")
					}

					if p.Reference == nil || *p.Reference != "zero" {
						return s.reject(ctx, p, RejectionNotInformed, "payment reference must be 'zero' for the first payment")
					}

					return s.updateStatus(ctx, p, payment.StatusACCP)
				}
			}

			if p.Date.Before(automatic.ReferenceStartDate) {
				return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment date is before the allowed start date")
			}

			now := timeutil.BrazilDateNow()
			if p.Date.Before(now.AddDate(0, 0, 2)) {
				return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment must be scheduled at least 2 days in advance")
			}

			if p.Date.After(now.AddDate(0, 0, 10)) {
				return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be scheduled more than 10 days in advance")
			}

			if automatic.FixedAmount != nil && p.Amount != *automatic.FixedAmount {
				return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment amount does not match the configured fixed amount in the consent")
			}

			if maxAmount := automatic.MaximumVariableAmount; maxAmount != nil && convertAmount(p.Amount) > convertAmount(*maxAmount) {
				return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "payment amount is greater than the configured maximum variable amount in the consent")
			}

			if minAmount := automatic.MinimumVariableAmount; minAmount != nil && convertAmount(p.Amount) < convertAmount(*minAmount) {
				return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "payment amount is less than the configured minimum variable amount in the consent")
			}

			lastPayment, err := s.payment(ctx, Query{
				ConsentID: c.ID.String(),
				Statuses:  []payment.Status{payment.StatusSCHD, payment.StatusACSC},
				Order:     "date DESC",
			}, c.OrgID)
			if err != nil {
				return err
			}

			// Skip interval validation if the last payment was the initial one.
			if lastPayment.Reference != nil && *lastPayment.Reference != "zero" {
				if automatic.Interval == IntervalWeekly && p.Date.StartOfWeek().Equal(lastPayment.Date.StartOfWeek()) {
					return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be scheduled more than once a week")
				}
				if automatic.Interval == IntervalMonthly && p.Date.StartOfMonth().Equal(lastPayment.Date.StartOfMonth()) {
					return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be scheduled more than once a month")
				}
				if automatic.Interval == IntervalAnnually && p.Date.StartOfYear().Equal(lastPayment.Date.StartOfYear()) {
					return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be scheduled more than once a year")
				}
				// TODO: Implement the other intervals.
			}
		}

		if sweeping := c.Configuration.Sweeping; sweeping != nil {
			if sweeping.TransactionLimit != nil && convertAmount(p.Amount) > convertAmount(*sweeping.TransactionLimit) {
				return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "sweeping payment amount is greater than the configured transaction limit in the consent")
			}

			if sweeping.TotalAllowedAmount != nil {
				_, currentTotalAmount, err := s.currentAmount(ctx, c, nil, nil)
				if err != nil {
					return err
				}
				if currentTotalAmount+convertAmount(p.Amount) > convertAmount(*sweeping.TotalAllowedAmount) {
					return s.reject(ctx, p, RejectionTotalConsentValueLimitExceeded, "sweeping payment amount is greater than the configured total allowed amount in the consent")
				}
			}

			if periodicLimits := sweeping.PeriodicLimits; periodicLimits != nil {
				if dayLimit := periodicLimits.Day; dayLimit != nil {
					today := timeutil.BrazilDateNow()
					numberOfPayments, currentAmount, err := s.currentAmount(ctx, c, &today, &today)
					if err != nil {
						return err
					}
					if dayLimit.Quantity != nil && numberOfPayments+1 > *dayLimit.Quantity {
						return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured daily limit quantity in the consent")
					}
					if dayLimit.TransactionLimit != nil && currentAmount+convertAmount(p.Amount) > convertAmount(*dayLimit.TransactionLimit) {
						return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured daily limit amount in the consent")
					}
				}

				if weekLimit := periodicLimits.Week; weekLimit != nil {
					today := timeutil.BrazilDateNow()
					startOfWeek := today.StartOfWeek()
					endOfWeek := today.EndOfWeek()
					numberOfPayments, currentAmount, err := s.currentAmount(ctx, c, &startOfWeek, &endOfWeek)
					if err != nil {
						return err
					}
					if weekLimit.Quantity != nil && numberOfPayments+1 > *weekLimit.Quantity {
						return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured weekly limit quantity in the consent")
					}
					if weekLimit.TransactionLimit != nil && currentAmount+convertAmount(p.Amount) > convertAmount(*weekLimit.TransactionLimit) {
						return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured weekly limit amount in the consent")
					}
				}

				if monthLimit := periodicLimits.Month; monthLimit != nil {
					today := timeutil.BrazilDateNow()
					startOfMonth := today.StartOfMonth()
					endOfMonth := today.EndOfMonth()
					numberOfPayments, currentAmount, err := s.currentAmount(ctx, c, &startOfMonth, &endOfMonth)
					if err != nil {
						return err
					}
					if monthLimit.Quantity != nil && numberOfPayments+1 > *monthLimit.Quantity {
						return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured monthly limit quantity in the consent")
					}
					if monthLimit.TransactionLimit != nil && currentAmount+convertAmount(p.Amount) > convertAmount(*monthLimit.TransactionLimit) {
						return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured monthly limit amount in the consent")
					}
				}

				if yearLimit := periodicLimits.Year; yearLimit != nil {
					today := timeutil.BrazilDateNow()
					startOfYear := today.StartOfYear()
					endOfYear := today.EndOfYear()
					numberOfPayments, currentAmount, err := s.currentAmount(ctx, c, &startOfYear, &endOfYear)
					if err != nil {
						return err
					}
					if yearLimit.Quantity != nil && numberOfPayments+1 > *yearLimit.Quantity {
						return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured yearly limit quantity in the consent")
					}
					if yearLimit.TransactionLimit != nil && currentAmount+convertAmount(p.Amount) > convertAmount(*yearLimit.TransactionLimit) {
						return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured yearly limit amount in the consent")
					}
				}
			}
		}
		return s.updateStatus(ctx, p, payment.StatusACCP)

	case payment.StatusACCP:
		if p.Date.After(timeutil.BrazilDateNow()) {
			return s.updateStatus(ctx, p, payment.StatusSCHD)
		}
		return s.updateStatus(ctx, p, payment.StatusACPD)

	case payment.StatusSCHD:
		if c.ExpiresAt != nil && p.Date.After(c.ExpiresAt.BrazilDate()) {
			return s.cancel(ctx, p, payment.CancelledFromHolder, bank.CNPJ)
		}
		if p.Date.After(timeutil.BrazilDateNow()) {
			return nil
		}
		return s.updateStatus(ctx, p, payment.StatusACPD)

	case payment.StatusACPD:
		return s.updateStatus(ctx, p, payment.StatusACSC)
	}

	return nil
}

func (s Service) updateStatus(ctx context.Context, p *Payment, status payment.Status) error {
	slog.DebugContext(ctx, "updating payment status", "current_status", p.Status, "new_status", status)

	p.Status = status
	p.StatusUpdatedAt = timeutil.DateTimeNow()
	p.UpdatedAt = timeutil.DateTimeNow()
	return s.save(ctx, p)
}

func (s Service) save(ctx context.Context, p *Payment) error {
	return s.db.WithContext(ctx).Save(p).Error
}

func (s Service) payment(ctx context.Context, query Query, orgID string) (*Payment, error) {
	dbQuery := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", query.ID)
	}
	if query.ConsentID != "" {
		dbQuery = dbQuery.Where("consent_id = ?", query.ConsentID)
	}
	if query.Statuses != nil {
		dbQuery = dbQuery.Where("status IN ?", query.Statuses)
	}
	if query.DebtorAccount {
		dbQuery = dbQuery.Preload("DebtorAccount")
	}
	if query.Order != "" {
		dbQuery = dbQuery.Order(query.Order)
	}
	p := &Payment{}
	if err := dbQuery.First(p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != p.ClientID {
		return nil, ErrClientNotAllowed
	}

	return p, nil
}

func (s Service) reject(ctx context.Context, p *Payment, code RejectionReasonCode, detail string) error {
	if !slices.Contains([]payment.Status{
		payment.StatusRCVD,
		payment.StatusPDNG,
		payment.StatusACCP,
		payment.StatusACPD,
		payment.StatusSCHD}, p.Status) {
		return errorutil.Format("%w: payment in status %s cannot be rejected", ErrRejectionNotAllowed, p.Status)
	}

	tomorrow := timeutil.BrazilDateNow().AddDate(0, 0, 1)
	if p.Status == payment.StatusSCHD && !p.Date.After(tomorrow) {
		return errorutil.Format("%w: scheduled payments until 23:59 of the next day must be maintained", ErrRejectionNotAllowed)
	}

	p.Rejection = &Rejection{
		Code:   code,
		Detail: detail,
	}
	return s.updateStatus(ctx, p, payment.StatusRJCT)
}

func (s Service) currentAmount(ctx context.Context, c *Consent, from *timeutil.BrazilDate, to *timeutil.BrazilDate) (int, float64, error) {
	payments, err := s.payments(ctx, c.OrgID, &Filter{
		ConsentID: c.ID.String(),
		Statuses:  []payment.Status{payment.StatusACSC, payment.StatusSCHD},
		From:      from,
		To:        to,
	})
	if err != nil {
		return 0, 0.0, nil
	}

	amount := 0.0
	for _, p := range payments {
		amount += convertAmount(p.Amount)
	}

	return len(payments), amount, nil
}

func (s Service) payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error) {
	if opts == nil {
		opts = &Filter{}
	}
	query := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if opts.ConsentID != "" {
		query = query.Where("consent_id = ?", strings.TrimPrefix(opts.ConsentID, consent.URNPrefix))
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
