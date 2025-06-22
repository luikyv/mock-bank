package autopayment

import (
	"context"
	"errors"
	"fmt"
	"github.com/luikyv/mock-bank/internal/bank"
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
}

func NewService(db *gorm.DB, userService user.Service, accountService account.Service) Service {
	return Service{db: db, userService: userService, accountService: accountService}
}

func (s Service) WithTx(tx *gorm.DB) Service {
	return NewService(tx, s.userService, s.accountService)
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

	u, err := s.userService.UserByCPF(ctx, c.UserIdentification, c.OrgID)
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

	now := timeutil.DateTimeNow()
	c.AuthorizedAt = &now
	return s.updateConsentStatus(ctx, c, ConsentStatusAuthorized)
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

func (s Service) validateConsentEdition(_ context.Context, c *Consent, edition ConsentEdition) error {
	if c.Status != ConsentStatusAuthorized {
		return errorutil.New("consent is not authorized")
	}

	if c.Status != ConsentStatusAuthorized {
		return ErrConsentNotAuthorized
	}

	if c.Configuration.Automatic == nil {
		return errorutil.New("edition is only allowed for automatic pix")
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
	p := &Payment{}
	// TODO: Should I always load this?
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

func (s Service) Payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error) {
	if opts == nil {
		opts = &Filter{}
	}
	query := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if opts.ConsentID != "" {
		query = query.Where("consent_id = ?", strings.TrimPrefix(opts.ConsentID, consent.URNPrefix))
	}

	var payments []*Payment
	if err := query.Find(&payments).Error; err != nil {
		return nil, fmt.Errorf("could not find payments: %w", err)
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

		if automatic.MaximumVariableAmount != nil && automatic.MinimumVariableAmount != nil && !compareAmounts(*automatic.MinimumVariableAmount, *automatic.MaximumVariableAmount) {
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

	if c.Configuration.Sweeping != nil {
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
	}

	if debtorAccount != nil && slices.Contains([]payment.AccountType{
		payment.AccountTypeCACC,
		payment.AccountTypeSVGS,
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
	return nil
}

func (s Service) runConsentPostCreationAutomations(ctx context.Context, c *Consent) error {
	switch c.Status {
	case ConsentStatusAwaitingAuthorization:
		now := timeutil.DateTimeNow()
		if now.After(c.CreatedAt.Add(60 * time.Minute).Time) {
			slog.DebugContext(ctx, "recurring consent awaiting authorization for too long, moving to rejected")
			return s.RejectConsent(ctx, c, ConsentRejection{
				By:     TerminatedByHolder,
				From:   TerminatedFromHolder,
				Code:   ConsentRejectionAuthorizationTimeout,
				Detail: "consent awaiting authorization for too long",
			})
		}
	case ConsentStatusAuthorized:
		now := timeutil.DateTimeNow()
		if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time) {
			slog.DebugContext(ctx, "recurring consent is authorized, but expired, moving to consumed")
			return s.updateConsentStatus(ctx, c, ConsentStatusConsumed)
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
	if c.Configuration.Sweeping != nil && p.RiskSignals == nil {
		return errorutil.New("risk signals is required for sweeping payments")
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
			if firstPayment := automatic.FirstPayment; firstPayment != nil && p.ID.String() == s.firstPaymentID(ctx, c.ID.String(), c.OrgID) {
				if !p.Date.Equal(firstPayment.Date) {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment date does not match the configured first payment date in the consent")
				}

				if p.Amount != firstPayment.Amount {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment amount does not match the configured first payment amount in the consent")
				}

				if p.Currency != firstPayment.Currency {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment currency does not match the configured first payment currency in the consent")
				}

				if p.CreditorAccountISBP != firstPayment.CreditorAccount.ISPB {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account isbp does not match the configured first payment creditor account isbp in the consent")
				}

				if p.CreditorAccountType != firstPayment.CreditorAccount.Type {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account type does not match the configured first payment creditor account type in the consent")
				}

				if !reflect.DeepEqual(p.CreditorAccountIssuer, firstPayment.CreditorAccount.Issuer) {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account issuer does not match the configured first payment creditor account issuer in the consent")
				}

				if p.CreditorAccountNumber != firstPayment.CreditorAccount.Number {
					return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment creditor account number does not match the configured first payment creditor account number in the consent")
				}

				if p.Reference == nil || *p.Reference != "zero" {
					return s.reject(ctx, p, RejectionNotInformed, "payment reference must be 'zero' for the first payment")
				}

				return s.updateStatus(ctx, p, payment.StatusACCP)
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

			if maxAmount := automatic.MaximumVariableAmount; maxAmount != nil && !compareAmounts(p.Amount, *maxAmount) {
				return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "payment amount is greater than the configured maximum variable amount in the consent")
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

func (s Service) countPayments(ctx context.Context, consentID string) (int64, error) {
	consentID = strings.TrimPrefix(consentID, consent.URNPrefix)
	var count int64
	if err := s.db.WithContext(ctx).Model(&Payment{}).Where("consent_id = ?", consentID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count recurring payments: %w", err)
	}

	return count, nil
}

func (s Service) firstPaymentID(ctx context.Context, consentID, orgID string) string {
	var p Payment
	err := s.db.WithContext(ctx).
		Where("consent_id = ? AND org_id = ?", consentID, orgID).
		Order("created_at ASC").
		Select("id").
		First(&p).
		Error

	if err != nil {
		slog.ErrorContext(ctx, "failed to get first payment id", "consent_id", consentID, "org_id", orgID, "error", err)
		return ""
	}

	return p.ID.String()
}
