package autopayment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/luikyv/mock-bank/internal/webhook"

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
	storage        Storage
	userService    user.Service
	accountService account.Service
	webhookService webhook.Service
}

func NewService(
	db *gorm.DB,
	userService user.Service,
	accountService account.Service,
	webhookService webhook.Service,
) Service {
	return Service{
		storage:        storage{db: db},
		userService:    userService,
		accountService: accountService,
		webhookService: webhookService,
	}
}

func (s Service) CreateConsent(ctx context.Context, c *Consent, debtorAcc *payment.Account) error {
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

		if automatic.MaximumVariableAmount != nil && automatic.MinimumVariableAmount != nil && payment.ConvertAmount(*automatic.MinimumVariableAmount) > payment.ConvertAmount(*automatic.MaximumVariableAmount) {
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

		if sweeping.StartDateTime != nil && c.ExpiresAt != nil && sweeping.StartDateTime.After(*c.ExpiresAt) {
			return errorutil.Format("%w: sweeping start date cannot be after expiration date", ErrInvalidData)
		}
	}

	if debtorAcc != nil && slices.Contains([]payment.AccountType{
		payment.AccountTypeCACC,
		payment.AccountTypeSVGS,
	}, debtorAcc.Type) && debtorAcc.Issuer == nil {
		return errorutil.New("debtor account issuer is required for account types CACC or SVGS")
	}

	u, err := s.userService.User(ctx, user.Query{CPF: c.UserIdentification}, c.OrgID)
	if err != nil {
		return fmt.Errorf("%w: could not find user", ErrInvalidPayment)
	}
	c.OwnerID = u.ID

	if c.BusinessIdentification != nil {
		business, err := s.userService.User(ctx, user.Query{CNPJ: *c.BusinessIdentification}, c.OrgID)
		if err != nil {
			return fmt.Errorf("%w: could not find business", ErrInvalidPayment)
		}
		c.OwnerID = business.ID
	}

	c.Status = ConsentStatusAwaitingAuthorization
	now := timeutil.DateTimeNow()
	c.StatusUpdatedAt = now
	c.CreatedAt = now
	c.UpdatedAt = now
	if sweeping := c.Configuration.Sweeping; sweeping != nil && sweeping.StartDateTime == nil {
		sweeping.StartDateTime = &now
	}

	if debtorAcc == nil {
		return s.storage.createConsent(ctx, c)
	}

	acc, err := s.accountService.Account(ctx, account.Query{Number: debtorAcc.Number}, c.OrgID)
	if err != nil {
		return err
	}

	if acc.OwnerID != c.OwnerID {
		return ErrUserDoesntMatchAccount
	}

	c.DebtorAccountID = &acc.ID
	return s.storage.createConsent(ctx, c)
}

func (s Service) AuthorizeConsent(ctx context.Context, c *Consent) error {

	if c.Status != ConsentStatusAwaitingAuthorization {
		return errorutil.Format("%w: consent is not awaiting authorization", ErrInvalidConsentStatus)
	}

	// Load debtor account if not already loaded.
	if c.DebtorAccount == nil && c.DebtorAccountID != nil {
		accID := *c.DebtorAccountID
		acc, err := s.accountService.Account(ctx, account.Query{ID: accID.String()}, c.OrgID)
		if err != nil {
			return err
		}
		c.DebtorAccount = acc
	}

	if c.DebtorAccount != nil && c.DebtorAccount.SubType == account.SubTypeJointSimple {
		tomorrow := timeutil.BrazilDateNow().AddDate(0, 0, 1)
		c.ApprovalDueAt = &tomorrow
		if err := s.updateConsentStatus(ctx, c, ConsentStatusPartiallyAccepted); err != nil {
			return err
		}
		return nil
	}

	return s.updateConsentStatus(ctx, c, ConsentStatusAuthorized)
}

func (s Service) EnrollConsent(ctx context.Context, id, orgID string, opts payment.EnrollmentOptions) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	if c.Status != ConsentStatusAwaitingAuthorization {
		return errorutil.Format("%w: consent is not awaiting authorization", ErrInvalidConsentStatus)
	}

	if c.UserIdentification != opts.UserIdentification {
		return errorutil.New("consent user identification mismatch")
	}

	if !reflect.DeepEqual(c.BusinessIdentification, opts.BusinessIdentification) {
		return errorutil.New("consent business identification mismatch")
	}

	if c.EnrollmentID != nil {
		return errorutil.New("consent already has an enrollment")
	}

	c.EnrollmentID = &opts.EnrollmentID
	c.DebtorAccountID = opts.DebtorAccountID
	c.EnrollmentChallenge = &opts.Challenge
	c.EnrollmentTransactionLimit = &opts.TransactionLimit
	c.EnrollmentDailyLimit = &opts.DailyLimit
	return s.updateConsent(ctx, c)
}

func (s Service) Consent(ctx context.Context, id, orgID string) (*Consent, error) {
	id = strings.TrimPrefix(id, ConsentURNPrefix)
	c, err := s.storage.consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != c.ClientID {
		return nil, ErrClientNotAllowed
	}

	switch c.Status {
	case ConsentStatusAwaitingAuthorization:
		if timeutil.DateTimeNow().After(c.CreatedAt.Add(60 * time.Minute)) {
			slog.DebugContext(ctx, "recurring consent awaiting authorization for too long, moving to rejected")
			return c, s.RejectConsent(ctx, c, ConsentRejection{
				By:     TerminatedByHolder,
				From:   payment.TerminatedFromHolder,
				Code:   ConsentRejectionAuthorizationTimeout,
				Detail: "consent awaiting authorization for too long",
			})
		}
	case ConsentStatusAuthorized:
		if c.ExpiresAt != nil && timeutil.DateTimeNow().After(*c.ExpiresAt) {
			slog.DebugContext(ctx, "recurring consent is authorized, but expired, moving to consumed")
			return c, s.updateConsentStatus(ctx, c, ConsentStatusConsumed)
		}
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
	if !slices.Contains([]ConsentStatus{ConsentStatusAwaitingAuthorization, ConsentStatusPartiallyAccepted}, c.Status) {
		return ErrCannotRejectConsent
	}

	c.Rejection = &rejection
	return s.updateConsentStatus(ctx, c, ConsentStatusRejected)
}

func (s Service) RevokeConsent(ctx context.Context, id, orgID string, revocation ConsentRevocation) (*Consent, error) {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if c.Status != ConsentStatusAuthorized {
		return nil, ErrInvalidConsentStatus
	}

	c.Revocation = &revocation
	if err := s.updateConsentStatus(ctx, c, ConsentStatusRevoked); err != nil {
		return nil, fmt.Errorf("could not revoke consent: %w", err)
	}

	payments, err := s.Payments(ctx, orgID, &Filter{
		ConsentID: id,
		Statuses:  []payment.Status{payment.StatusPDNG, payment.StatusSCHD}},
	)
	if err != nil {
		return nil, err
	}
	for _, p := range payments {
		if err := s.cancel(ctx, p, payment.TerminatedFromInitiator, c.UserIdentification); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (s Service) EditConsent(ctx context.Context, id, orgID string, edition ConsentEdition) (*Consent, error) {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if c.Status != ConsentStatusAuthorized {
		return nil, errorutil.Format("%w: consent is not authorized", ErrInvalidConsentStatus)
	}

	if c.Configuration.Automatic == nil {
		return nil, errorutil.Format("%w: edition is only allowed for automatic pix", ErrFieldNotAllowed)
	}

	if edition.LoggedUser == nil || edition.LoggedUser.Document.Identification == "" {
		return nil, errorutil.Format("%w: logged user identification is required", ErrMissingValue)
	}

	if edition.LoggedUser.Document.Identification != c.UserIdentification {
		return nil, errorutil.Format("%w: logged user identification doesn't match the consent", ErrInvalidEdition)
	}

	if edition.RiskSignals == nil {
		return nil, errorutil.Format("%w: edition risk signals are required for automatic pix edition", ErrInvalidEdition)
	}

	if len(edition.Creditors) != 1 {
		return nil, errorutil.New("only one creditor is allowed for automatic pix edition")
	}

	if edition.ExpiresAt != nil && edition.ExpiresAt.Before(timeutil.DateTimeNow()) {
		return nil, errorutil.Format("%w: edition expiration cannot be in the past", ErrInvalidEdition)
	}

	if edition.RecurringConfiguration != nil && edition.RecurringConfiguration.Automatic != nil && edition.RecurringConfiguration.Automatic.MaximumVariableAmount != nil {
		config := c.Configuration.Automatic
		maxVariableAmount := *edition.RecurringConfiguration.Automatic.MaximumVariableAmount
		if config.MinimumVariableAmount != nil && payment.ConvertAmount(*config.MinimumVariableAmount) > payment.ConvertAmount(maxVariableAmount) {
			return nil, errorutil.Format("%w: maximum variable amount is less than the minimum variable amount in the consent", ErrInvalidEdition)
		}

		if config.FixedAmount != nil {
			return nil, errorutil.Format("%w: maximum variable amount is not allowed for fixed amount consents", ErrInvalidEdition)
		}
	}

	c.RiskSignals = edition.RiskSignals
	for i := range c.Creditors {
		c.Creditors[i].Name = edition.Creditors[0].Name
	}
	c.ExpiresAt = edition.ExpiresAt
	var maxVariableAmount *string
	if edition.RecurringConfiguration != nil && edition.RecurringConfiguration.Automatic != nil {
		maxVariableAmount = edition.RecurringConfiguration.Automatic.MaximumVariableAmount
	}
	c.Configuration.Automatic.MaximumVariableAmount = maxVariableAmount

	payments, err := s.Payments(ctx, orgID, &Filter{
		ConsentID: id,
		Statuses:  []payment.Status{payment.StatusRCVD, payment.StatusPDNG, payment.StatusACCP, payment.StatusSCHD},
	})
	if err != nil {
		return nil, fmt.Errorf("could not fetch payments: %w", err)
	}
	for _, p := range payments {
		if c.ExpiresAt != nil && p.Date.After(c.ExpiresAt.BrazilDate()) {
			if err := s.cancel(ctx, p, payment.TerminatedFromHolder, c.UserIdentification); err != nil {
				return nil, err
			}
		}
	}

	return c, s.updateConsent(ctx, c)
}

func (s Service) Create(ctx context.Context, p *Payment) error {

	if p.ConsentID == uuid.Nil {
		return errorutil.Format("%w: could not infer consent id", ErrMissingValue)
	}

	c, err := s.Consent(ctx, p.ConsentID.String(), p.OrgID)
	if err != nil {
		return err
	}

	if c.Status == ConsentStatusPartiallyAccepted {
		return ErrConsentPartiallyAccepted
	}

	if c.Status != ConsentStatusAuthorized {
		return ErrInvalidConsentStatus
	}

	if !reflect.DeepEqual(c.EnrollmentID, p.EnrollmentID) {
		return errorutil.Format("%w: payment enrollment id doesn't match the consent", ErrPaymentDoesNotMatchConsent)
	}

	if p.EnrollmentID != nil && (p.AuthorisationFlow == nil || *p.AuthorisationFlow != payment.AuthorisationFlowFIDOFlow) {
		return errorutil.New("payment enrollment id is set but authorisation flow is not FIDO")
	}

	if sweeping := c.Configuration.Sweeping; sweeping != nil {
		if p.RiskSignals == nil {
			return errorutil.New("risk signals is required for sweeping payments")
		}

		if sweeping.StartDateTime != nil && p.Date.Before(sweeping.StartDateTime.BrazilDate()) {
			return errorutil.Format("%w: payment date cannot be after sweeping start date", ErrPaymentDoesNotMatchConsent)
		}
	}

	if c.Configuration.Automatic != nil {
		if p.Reference == nil {
			return errorutil.Format("%w: payment reference is required for automatic payments", ErrInvalidPayment)
		}

		if *p.Reference != "zero" && p.LocalInstrument != payment.LocalInstrumentAUTO {
			return errorutil.Format("%w: local instrument must be AUTO for recurring automatic payments", ErrInvalidPayment)
		}

		if *p.Reference == "zero" && p.LocalInstrument != payment.LocalInstrumentMANU {
			return errorutil.Format("%w: local instrument must be MANU for non-recurring automatic payments", ErrInvalidPayment)
		}
	}

	endToEndDate, err := payment.ParseEndToEndDate(p.EndToEndID)
	if err != nil {
		return errorutil.Format("%w: invalid end to end id date: %w", ErrInvalidEndToEndID, err)
	}

	if !p.Date.Equal(endToEndDate.BrazilDate()) {
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

	p.Status = payment.StatusRCVD
	p.StatusUpdatedAt = timeutil.DateTimeNow()
	p.DebtorAccountID = c.DebtorAccountID
	p.DebtorAccount = c.DebtorAccount
	p.Date = endToEndDate.BrazilDate()
	p.CreatedAt = timeutil.DateTimeNow()
	p.UpdatedAt = timeutil.DateTimeNow()

	if err := s.storage.create(ctx, p); err != nil {
		return err
	}
	slog.DebugContext(ctx, "recurring payment created", "id", p.ID)

	go func() {
		acceptOrSchedule := func(ctx context.Context, p *Payment, c *Consent) error {
			if p.Date.After(timeutil.BrazilDateNow()) {
				return s.updateStatus(ctx, p, payment.StatusSCHD)
			}
			// Consume the consent if it has reached the sweeping total allowed amount.
			if c.Configuration.Sweeping != nil && c.Configuration.Sweeping.TotalAllowedAmount != nil {
				payments, err := s.Payments(ctx, c.OrgID, &Filter{ConsentID: c.ID.String(), Statuses: []payment.Status{payment.StatusACSC}})
				if err != nil {
					return fmt.Errorf("failed to fetch payments: %w", err)
				}
				if payment.SumPayments(payments)+payment.ConvertAmount(p.Amount) >= payment.ConvertAmount(*c.Configuration.Sweeping.TotalAllowedAmount) {
					if err := s.updateConsentStatus(ctx, c, ConsentStatusConsumed); err != nil {
						return err
					}
				}
			}
			return s.updateStatus(ctx, p, payment.StatusACSC)
		}

		run := func(ctx context.Context, p *Payment, c *Consent) error {
			switch p.Status {
			case payment.StatusRCVD:
				if c.ExpiresAt != nil && p.Date.After(c.ExpiresAt.BrazilDate()) {
					return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be received after the consent expiration date")
				}

				if automatic := c.Configuration.Automatic; automatic != nil {

					if firstPaymentConfig := automatic.FirstPayment; firstPaymentConfig != nil {
						firstPayment, err := s.Payment(ctx, Query{ConsentID: c.ID.String(), Order: "created_at ASC"}, c.OrgID)
						if err != nil {
							return fmt.Errorf("could not load first payment for payment automation: %w", err)
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

							_, err := s.accountService.Account(ctx, account.Query{Number: p.CreditorAccountNumber}, c.OrgID)
							if err != nil {
								if errors.Is(err, account.ErrNotFound) {
									return s.reject(ctx, p, RejectionInconsistentOwnership, "invalid creditor account number")
								}
								return err
							}

							return acceptOrSchedule(ctx, p, c)
						}
					}

					if p.Date.Before(automatic.ReferenceStartDate) {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment date is before the allowed start date")
					}

					today := timeutil.BrazilDateNow()
					if p.Date.Before(today.AddDate(0, 0, 2)) {
						return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment must be scheduled at least 2 days in advance")
					}

					if p.Date.After(today.AddDate(0, 0, 10)) {
						return s.reject(ctx, p, RejectionOutOfAllowedPeriod, "payment cannot be scheduled more than 10 days in advance")
					}

					if automatic.FixedAmount != nil && p.Amount != *automatic.FixedAmount {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment amount does not match the configured fixed amount in the consent")
					}

					if maxAmount := automatic.MaximumVariableAmount; maxAmount != nil && payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*maxAmount) {
						return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "payment amount is greater than the configured maximum variable amount in the consent")
					}
				}

				if sweeping := c.Configuration.Sweeping; sweeping != nil {
					creditors := make([]string, len(c.Creditors))
					for i, creditor := range c.Creditors {
						creditors[i] = creditor.CPFCNPJ
					}

					if !slices.Contains(creditors, p.DocumentIdentification) {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor doesn't match any of the creditors in the consent")
					}

					if p.Proxy != nil && !slices.Contains(creditors, *p.Proxy) {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "payment proxy doesn't match any of the creditors in the consent")
					}

					if sweeping.TransactionLimit != nil && payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*sweeping.TransactionLimit) {
						return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "sweeping payment amount is greater than the configured transaction limit in the consent")
					}

					if sweeping.TotalAllowedAmount != nil {
						payments, err := s.Payments(ctx, c.OrgID, &Filter{ConsentID: c.ID.String(), Statuses: []payment.Status{payment.StatusACSC}})
						if err != nil {
							return fmt.Errorf("failed to fetch payments: %w", err)
						}
						if payment.SumPayments(payments)+payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*sweeping.TotalAllowedAmount) {
							return s.reject(ctx, p, RejectionTotalConsentValueLimitExceeded, "sweeping payment amount is greater than the configured total allowed amount in the consent")
						}
					}

					if periodicLimits := sweeping.PeriodicLimits; periodicLimits != nil {
						if dayLimit := periodicLimits.Day; dayLimit != nil {
							today := timeutil.BrazilDateNow()
							payments, err := s.Payments(ctx, c.OrgID, &Filter{
								ConsentID: c.ID.String(),
								Statuses:  []payment.Status{payment.StatusACSC, payment.StatusSCHD},
								From:      &today,
								To:        &today,
							})
							if err != nil {
								return err
							}
							if dayLimit.Quantity != nil && len(payments)+1 > *dayLimit.Quantity {
								return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured daily limit quantity in the consent")
							}
							if dayLimit.TransactionLimit != nil && payment.SumPayments(payments)+payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*dayLimit.TransactionLimit) {
								return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured daily limit amount in the consent")
							}
						}

						if weekLimit := periodicLimits.Week; weekLimit != nil {
							today := timeutil.BrazilDateNow()
							startOfWeek := today.StartOfWeek()
							endOfWeek := today.EndOfWeek()
							payments, err := s.Payments(ctx, c.OrgID, &Filter{
								ConsentID: c.ID.String(),
								Statuses:  []payment.Status{payment.StatusACSC, payment.StatusSCHD},
								From:      &startOfWeek,
								To:        &endOfWeek,
							})
							if err != nil {
								return err
							}
							if weekLimit.Quantity != nil && len(payments)+1 > *weekLimit.Quantity {
								return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured weekly limit quantity in the consent")
							}
							if weekLimit.TransactionLimit != nil && payment.SumPayments(payments)+payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*weekLimit.TransactionLimit) {
								return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured weekly limit amount in the consent")
							}
						}

						if monthLimit := periodicLimits.Month; monthLimit != nil {
							today := timeutil.BrazilDateNow()
							startOfMonth := today.StartOfMonth()
							endOfMonth := today.EndOfMonth()
							payments, err := s.Payments(ctx, c.OrgID, &Filter{
								ConsentID: c.ID.String(),
								Statuses:  []payment.Status{payment.StatusACSC, payment.StatusSCHD},
								From:      &startOfMonth,
								To:        &endOfMonth,
							})
							if err != nil {
								return fmt.Errorf("failed to fetch payments: %w", err)
							}
							if monthLimit.Quantity != nil && len(payments)+1 > *monthLimit.Quantity {
								return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured monthly limit quantity in the consent")
							}
							if monthLimit.TransactionLimit != nil && payment.SumPayments(payments)+payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*monthLimit.TransactionLimit) {
								return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured monthly limit amount in the consent")
							}
						}

						if yearLimit := periodicLimits.Year; yearLimit != nil {
							today := timeutil.BrazilDateNow()
							startOfYear := today.StartOfYear()
							endOfYear := today.EndOfYear()
							payments, err := s.Payments(ctx, c.OrgID, &Filter{
								ConsentID: c.ID.String(),
								Statuses:  []payment.Status{payment.StatusACSC, payment.StatusSCHD},
								From:      &startOfYear,
								To:        &endOfYear,
							})
							if err != nil {
								return err
							}
							if yearLimit.Quantity != nil && len(payments)+1 > *yearLimit.Quantity {
								return s.reject(ctx, p, RejectionPeriodQuantityLimitExceeded, "sweeping payment amount is greater than the configured yearly limit quantity in the consent")
							}
							if yearLimit.TransactionLimit != nil && payment.SumPayments(payments)+payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*yearLimit.TransactionLimit) {
								return s.reject(ctx, p, RejectionPeriodValueLimitExceeded, "sweeping payment amount is greater than the configured yearly limit amount in the consent")
							}
						}
					}

					creditorAcc, err := s.accountService.Account(ctx, account.Query{Number: p.CreditorAccountNumber}, p.OrgID)
					if err != nil {
						if errors.Is(err, account.ErrNotFound) {
							return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor account not found")
						}
						return err
					}
					if creditorAcc.OwnerID != c.OwnerID {
						return s.reject(ctx, p, RejectionPaymentConsentMismatch, "creditor account owner does not match the consent")
					}
				}

				if c.EnrollmentTransactionLimit != nil && payment.ConvertAmount(p.Amount) > payment.ConvertAmount(*c.EnrollmentTransactionLimit) {
					return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "payment amount is greater than the configured transaction limit in the consent")
				}

				if c.EnrollmentDailyLimit != nil {
					today := timeutil.BrazilDateNow()
					payments, err := s.Payments(ctx, c.OrgID, &Filter{
						EnrollmentID: p.EnrollmentID.String(),
						Statuses:     []payment.Status{payment.StatusACSC, payment.StatusSCHD},
						From:         &today,
						To:           &today,
					})
					if err != nil {
						return fmt.Errorf("failed to fetch payments: %w", err)
					}
					if payment.ConvertAmount(p.Amount)+payment.SumPayments(payments) > payment.ConvertAmount(*c.EnrollmentDailyLimit) {
						return s.reject(ctx, p, RejectionTransactionValueLimitExceeded, "payment amount goes beyond the configured daily limit in the consent")
					}
				}

				return acceptOrSchedule(ctx, p, c)
			default:
				return nil
			}
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p, err := s.Payment(ctx, Query{ID: p.ID.String()}, p.OrgID)
				if err != nil {
					slog.ErrorContext(ctx, "error loading payment for recurring payment automation", "id", p.ID, "error", err)
					return
				}

				c, err := s.Consent(ctx, p.ConsentID.String(), p.OrgID)
				if err != nil {
					slog.ErrorContext(ctx, "error loading consent for recurring payment automation", "id", p.ID, "error", err)
					return
				}

				if err := run(ctx, p, c); err != nil {
					slog.ErrorContext(ctx, "error running recurring payment automations for payment", "id", p.ID, "error", err)
					return
				}

				if slices.Contains([]payment.Status{
					payment.StatusCANC,
					payment.StatusRJCT,
					payment.StatusACSC,
					payment.StatusSCHD,
				}, p.Status) {
					slog.DebugContext(ctx, "recurring payment automation completed, stopping ticker", "id", p.ID)
					return
				}
			case <-ctx.Done():
				slog.DebugContext(ctx, "recurring payment automation deadline reached, stopping ticker", "id", p.ID)
				return
			}
		}
	}()

	return nil
}

func (s Service) Payment(ctx context.Context, query Query, orgID string) (*Payment, error) {
	p, err := s.storage.payment(ctx, query, orgID)
	if err != nil {
		return nil, err
	}

	if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != p.ClientID {
		return nil, ErrClientNotAllowed
	}

	return p, nil
}

func (s Service) Payments(ctx context.Context, orgID string, opts *Filter) ([]*Payment, error) {
	payments, err := s.storage.payments(ctx, orgID, opts)
	if err != nil {
		return nil, err
	}

	for _, p := range payments {
		if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != p.ClientID {
			return nil, ErrClientNotAllowed
		}
	}

	return payments, nil
}

func (s Service) Cancel(ctx context.Context, id, orgID string, doc consent.Document) (*Payment, error) {
	p, err := s.Payment(ctx, Query{ID: id, DebtorAccount: true}, orgID)
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

	if err := s.cancel(ctx, p, payment.TerminatedFromInitiator, c.UserIdentification); err != nil {
		return nil, err
	}

	return p, nil
}

func (s Service) updateConsentStatus(ctx context.Context, c *Consent, status ConsentStatus) error {
	oldStatus := c.Status
	slog.DebugContext(ctx, "updating recurring payment consent status", "current_status", oldStatus, "new_status", status)

	c.Status = status
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	if status == ConsentStatusAuthorized {
		now := timeutil.DateTimeNow()
		c.AuthorizedAt = &now
	}

	if slices.Contains([]ConsentStatus{
		ConsentStatusConsumed,
		ConsentStatusRejected,
		ConsentStatusRevoked,
	}, status) {
		slog.DebugContext(ctx, "notifying client about automatic payment consent status change", "status", c.Status)
		s.webhookService.NotifyRecurringPaymentConsent(ctx, c.ClientID, c.URN(), c.Version)
	}

	return s.updateConsent(ctx, c)
}

func (s Service) updateConsent(ctx context.Context, c *Consent) error {
	c.UpdatedAt = timeutil.DateTimeNow()
	return s.storage.updateConsent(ctx, c)
}

func (s Service) reject(ctx context.Context, p *Payment, code RejectionReasonCode, detail string) error {
	if !slices.Contains([]payment.Status{
		payment.StatusRCVD,
		payment.StatusPDNG,
		payment.StatusACCP,
		payment.StatusACPD,
		payment.StatusSCHD,
	}, p.Status) {
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

func (s Service) cancel(ctx context.Context, p *Payment, from payment.TerminatedFrom, by string) error {
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

func (s Service) updateStatus(ctx context.Context, p *Payment, status payment.Status) error {
	slog.DebugContext(ctx, "updating payment status", "current_status", p.Status, "new_status", status)

	p.Status = status
	p.StatusUpdatedAt = timeutil.DateTimeNow()
	p.UpdatedAt = timeutil.DateTimeNow()
	if err := s.storage.update(ctx, p); err != nil {
		return err
	}

	if slices.Contains([]payment.Status{
		payment.StatusSCHD,
		payment.StatusACPD,
		payment.StatusRJCT,
	}, status) {
		s.webhookService.NotifyRecurringPayment(ctx, p.ClientID, p.ID.String(), p.Version)
	}

	return nil
}
