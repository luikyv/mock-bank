package autopayment

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/errorutil"
	"github.com/luiky/mock-bank/internal/payment"
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

func (s Service) CreateConsent(ctx context.Context, c *Consent, debtorAcc *payment.Account) error {
	c.Status = ConsentStatusAwaitingAuthorization

	if err := s.validateConsent(ctx, c, debtorAcc); err != nil {
		return err
	}

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

	now := timeutil.DateTimeNow()
	c.AuthorizedAt = &now
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

func (s Service) RejectConsent(ctx context.Context, id, orgID string, rejection ConsentRejection) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	return s.rejectConsent(ctx, c, rejection)
}

// func (s Service) Create(ctx context.Context, p *Payment) error {

// 	if p.ConsentID == uuid.Nil {
// 		return errorutil.New("could not infer consent id")
// 	}

// 	c, err := s.Consent(ctx, p.ConsentID.String(), p.OrgID)
// 	if err != nil {
// 		return err
// 	}

// 	if c.Status != ConsentStatusAuthorized {
// 		return ErrConsentNotAuthorized
// 	}

// 	if err := s.validatePayment(ctx, c, p); err != nil {
// 		return err
// 	}

// 	p.Status = payment.StatusRCVD
// 	p.DebtorAccountID = c.DebtorAccountID
// 	p.DebtorAccount = c.DebtorAccount
// 	date, _ := payment.ParseEndToEndDate(p.EndToEndID)
// 	p.Date = date.BrazilDate()

// 	if err := s.runPreCreationAutomations(ctx, p); err != nil {
// 		return err
// 	}
// 	return s.db.Create(p).Error
// }

// func (s Service) Payment(ctx context.Context, id, orgID string) (*Payment, error) {
// 	p := &Payment{}
// 	if err := s.db.WithContext(ctx).Preload("DebtorAccount").First(p, "id = ? AND org_id = ?", id, orgID).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return nil, ErrNotFound
// 		}
// 		return nil, err
// 	}

// 	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != p.ClientID {
// 		return nil, ErrClientNotAllowed
// 	}

// 	if err := s.runPostCreationAutomations(ctx, p); err != nil {
// 		return nil, err
// 	}

// 	return p, nil
// }

// func (s Service) Cancel(ctx context.Context, id, orgID string, doc payment.Document) (*Payment, error) {
// 	p, err := s.Payment(ctx, id, orgID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	c, err := s.Consent(ctx, p.ConsentID.String(), orgID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if doc.Rel != "CPF" {
// 		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
// 	}

// 	if c.UserCPF != doc.Identification {
// 		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
// 	}

// 	if err := s.cancel(ctx, p, payment.CancelledFromInitiator, c.UserCPF); err != nil {
// 		return nil, err
// 	}

// 	return p, nil
// }

// func (s Service) CancelAll(ctx context.Context, consentID, orgID string, doc payment.Document) ([]*Payment, error) {
// 	c, err := s.Consent(ctx, consentID, orgID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if doc.Rel != "CPF" {
// 		return nil, errorutil.Format("%w: invalid rel", ErrCancelNotAllowed)
// 	}

// 	if c.UserCPF != doc.Identification {
// 		return nil, errorutil.Format("%w: invalid identification", ErrCancelNotAllowed)
// 	}

// 	var payments []*Payment
// 	if err := s.db.WithContext(ctx).
// 		Where("consent_id = ? AND org_id = ?", c.ID, orgID).
// 		Find(&payments).Error; err != nil {
// 		return nil, fmt.Errorf("could not find payments: %w", err)
// 	}

// 	var cancelled []*Payment
// 	var cancelErrs error
// 	for _, p := range payments {
// 		if err := s.cancel(ctx, p, payment.CancelledFromInitiator, c.UserCPF); err != nil {
// 			if !errors.Is(err, ErrCancelNotAllowed) {
// 				return nil, err
// 			}
// 			cancelErrs = errors.Join(cancelErrs, err)
// 			continue
// 		}
// 		cancelled = append(cancelled, p)
// 	}

// 	if len(cancelled) == 0 {
// 		return nil, errorutil.Format("no payment could be cancelled: %w", cancelErrs)
// 	}

// 	return cancelled, nil
// }

// func (s Service) cancel(ctx context.Context, p *Payment, from payment.CancelledFrom, by string) error {
// 	if !slices.Contains([]payment.Status{payment.StatusPDNG, payment.StatusSCHD}, p.Status) {
// 		return errorutil.Format("%w: payment with status %s cannot be cancelled, only payments with status PDNG or SCHD can be cancelled", ErrCancelNotAllowed, p.Status)
// 	}

// 	if p.Status == payment.StatusSCHD && !timeutil.BrazilDateNow().Before(p.Date) {
// 		return errorutil.Format("%w: scheduled payments can only be cancelled until 23:59 (BRT) of the day before the payment date (%s)", ErrCancelNotAllowed, p.Date.String())
// 	}

// 	reason := payment.CancellationReasonPending
// 	if p.Status == payment.StatusSCHD {
// 		reason = payment.CancellationReasonScheduled
// 	}
// 	p.Cancellation = &payment.Cancellation{
// 		At:     timeutil.DateTimeNow(),
// 		Reason: reason,
// 		From:   from,
// 		By:     by,
// 	}
// 	return s.updateStatus(ctx, p, payment.StatusCANC)
// }

func (s Service) createConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Create(c).Error
}

func (s Service) validateConsent(_ context.Context, c *Consent, debtorAccount *payment.Account) error {
	if automatic := c.Configuration.Automatic; automatic != nil {
		if len(c.Creditors) != 1 {
			return errorutil.Format("%w: only one creditor is allowed for automatic pix", ErrInvalidPayment)
		}

		if c.Creditors[0].Type == payment.CreditorTypeIndividual {
			return errorutil.Format("%w: creditor of type INDIVIDUAL is not allowed for automatic pix", ErrInvalidPayment)
		}

		if automatic.FixedAmount != nil && automatic.MaximumVariableAmount != nil {
			return errorutil.Format("%w: at most one of fixedAmount and maximumVariableAmount can be informed", ErrInvalidPayment)
		}

		if automatic.MaximumVariableAmount != nil && automatic.MinimumVariableAmount != nil {
			max, _ := strconv.ParseFloat(*automatic.MaximumVariableAmount, 64)
			min, _ := strconv.ParseFloat(*automatic.MinimumVariableAmount, 64)
			if min > max {
				return errorutil.Format("%w: maximumVariableAmount cannot be lower than minimumVariableAmount", ErrInvalidPayment)
			}
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

			today := timeutil.BrazilDateNow()
			if firstPayment.Date.Before(today) {
				return errorutil.Format("%w: first payment date cannot be in the past", ErrInvalidDate)
			}
		}
	}

	if c.Configuration.Sweeping != nil {
		if businessCNPJ := c.BusinessCNPJ; businessCNPJ != nil {
			baseRootCNPJ := (*businessCNPJ)[:8]
			for _, creditor := range c.Creditors {
				if creditor.Type != payment.CreditorTypeCompany {
					return errorutil.Format("%w: sweeping requires all creditors to be companies when the user is business", ErrInvalidPayment)
				}

				if !strings.HasPrefix(creditor.CPFCNPJ, baseRootCNPJ) {
					return errorutil.Format("%w: sweeping requires all creditor CNPJs to share the same root as the user's business CNPJ", ErrInvalidPayment)
				}
			}
		} else {
			if len(c.Creditors) != 1 {
				return errorutil.Format("%w: sweeping requires exactly one creditor when the user is INDIVIDUAL", ErrInvalidPayment)
			}

			creditor := c.Creditors[0]
			if creditor.Type != payment.CreditorTypeIndividual {
				return errorutil.Format("%w: sweeping requires the creditor to be of type INDIVIDUAL when the user is a person", ErrInvalidPayment)
			}

			if creditor.CPFCNPJ != c.UserCPF {
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
	return nil
}

func (s Service) rejectConsent(ctx context.Context, c *Consent, rejection ConsentRejection) error {
	if c.Status == ConsentStatusRejected {
		return ErrConsentAlreadyRejected
	}

	c.Rejection = &rejection
	return s.updateConsentStatus(ctx, c, ConsentStatusRejected)
}

func (s Service) saveConsent(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Save(c).Error
}

// func (s Service) validatePayment(_ context.Context, c *Consent, p *Payment) error {

// 	endToEndDate, err := payment.ParseEndToEndDate(p.EndToEndID)
// 	if err != nil {
// 		return errorutil.Format("%w: invalid end to end id date: %w", ErrInvalidEndToEndID, err)
// 	}

// 	if p.Date != endToEndDate.BrazilDate() {
// 		return errorutil.Format("%w: end to end id date doesn't match the payment date", ErrInvalidEndToEndID)
// 	}

// 	// if p.CreditorAccount.ISBP != c.CreditorAccount.ISBP {
// 	// 	return errorutil.Format("%w: creditor account isbp does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
// 	// }

// 	// if !reflect.DeepEqual(p.CreditorAccount.Issuer, c.CreditorAccount.Issuer) {
// 	// 	return errorutil.Format("%w: creditor account issuer does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
// 	// }

// 	// if p.CreditorAccount.Number != c.CreditorAccount.Number {
// 	// 	return errorutil.Format("%w: creditor account number does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
// 	// }

// 	// if p.CreditorAccount.Type != c.CreditorAccount.Type {
// 	// 	return errorutil.Format("%w: creditor account type does not match the value specified in the consent", ErrPaymentDoesNotMatchConsent)
// 	// }

// 	if slices.Contains([]payment.LocalInstrument{
// 		payment.LocalInstrumentMANU,
// 		payment.LocalInstrumentDICT,
// 	}, p.LocalInstrument) && p.TransactionIdentification != nil {
// 		return errorutil.New("invalid consent: transaction identification is not allowed if local instrument is MANU or DICT")
// 	}

// 	return nil
// }

// func (s Service) runPreCreationAutomations(_ context.Context, p *Payment) error {
// 	switch p.Amount {
// 	case "20422.01":
// 		return ErrInvalidPayment
// 	default:
// 		return nil
// 	}
// }

// func (s Service) runPostCreationAutomations(ctx context.Context, p *Payment) error {
// 	now := timeutil.Now()
// 	if now.Before(p.UpdatedAt.Time.Add(5 * time.Second)) {
// 		slog.DebugContext(ctx, "payment was updated less than 5 secs ago, skipping transitions", "updated_at", p.UpdatedAt.String())
// 		return nil
// 	}

// 	slog.DebugContext(ctx, "evaluating payment automations", "status", p.Status, "amount", p.Amount)

// 	switch p.Status {
// 	case payment.StatusRCVD:
// 		return s.updateStatus(ctx, p, payment.StatusACCP)

// 	case payment.StatusACCP:
// 		today := timeutil.BrazilDateNow()
// 		if p.Date.After(today) {
// 			return s.updateStatus(ctx, p, payment.StatusSCHD)
// 		}
// 		return s.updateStatus(ctx, p, payment.StatusACPD)

// 	case payment.StatusSCHD:
// 		today := timeutil.BrazilDateNow()
// 		if p.Date.After(today) {
// 			return nil
// 		}
// 		return s.updateStatus(ctx, p, payment.StatusACPD)

// 	case payment.StatusACPD:
// 		return s.updateStatus(ctx, p, payment.StatusACSC)
// 	}

// 	return nil
// }

// func (s Service) updateStatus(ctx context.Context, p *Payment, status payment.Status) error {
// 	slog.DebugContext(ctx, "updating payment status", "current_status", p.Status, "new_status", status)

// 	p.Status = status
// 	p.StatusUpdatedAt = timeutil.DateTimeNow()
// 	p.UpdatedAt = timeutil.DateTimeNow()
// 	return s.save(ctx, p)
// }

// func (s Service) save(ctx context.Context, p *Payment) error {
// 	return s.db.WithContext(ctx).Save(p).Error
// }

// func (s Service) reject(ctx context.Context, p *Payment, code RejectionReasonCode, detail string) error {
// 	p.Rejection = &Rejection{
// 		Code:   code,
// 		Detail: detail,
// 	}
// 	return s.updateStatus(ctx, p, payment.StatusRJCT)
// }
