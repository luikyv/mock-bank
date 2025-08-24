package enrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"github.com/luikyv/mock-bank/internal/webhook"
	"gorm.io/gorm"
)

type Service struct {
	db                 *gorm.DB
	userService        user.Service
	accountService     account.Service
	paymentService     payment.Service
	autopaymentService autopayment.Service
	webhookService     webhook.Service
}

func NewService(
	db *gorm.DB,
	userService user.Service,
	accountService account.Service,
	paymentService payment.Service,
	autopaymentService autopayment.Service,
	webhookService webhook.Service,
) Service {
	return Service{
		db:                 db,
		userService:        userService,
		accountService:     accountService,
		paymentService:     paymentService,
		autopaymentService: autopaymentService,
		webhookService:     webhookService,
	}
}

func (s Service) Create(ctx context.Context, e *Enrollment, debtorAcc *payment.Account) error {
	e.Status = StatusAwaitingRiskSignals
	now := timeutil.DateTimeNow()
	e.StatusUpdatedAt = now
	e.CreatedAt = now
	e.UpdatedAt = now

	if err := s.validate(ctx, e, debtorAcc); err != nil {
		return err
	}

	u, err := s.userService.User(ctx, user.Query{CPF: e.UserIdentification}, e.OrgID)
	if err != nil {
		return err
	}
	e.OwnerID = u.ID

	if e.BusinessIdentification != nil {
		business, err := s.userService.User(ctx, user.Query{CNPJ: *e.BusinessIdentification}, e.OrgID)
		if err != nil {
			return err
		}
		e.OwnerID = business.ID
	}

	if debtorAcc == nil {
		return s.db.WithContext(ctx).Create(e).Error
	}

	acc, err := s.accountService.Account(ctx, account.Query{Number: debtorAcc.Number}, e.OrgID)
	if err != nil {
		return err
	}

	if acc.OwnerID != e.OwnerID {
		return ErrUserDoesntMatchAccount
	}

	e.DebtorAccountID = &acc.ID
	return s.db.WithContext(ctx).Create(e).Error
}

func (s Service) AddRiskSignals(ctx context.Context, id, orgID string, riskSignals map[string]any) error {
	e, err := s.Enrollment(ctx, Query{ID: id}, orgID)
	if err != nil {
		return err
	}

	if e.Status != StatusAwaitingRiskSignals {
		return errorutil.New("enrollment is not in awaiting risk signals status")
	}

	e.RiskSignals = &riskSignals
	return s.updateStatus(ctx, e, StatusAwaitingAccountHolderValidation)
}

func (s Service) AllowEnrollment(ctx context.Context, e *Enrollment) error {
	if e.Status != StatusAwaitingAccountHolderValidation {
		return errorutil.New("enrollment is not in awaiting account holder validation status")
	}

	if e.DailyLimit == nil {
		dailyLimit := defaultDailyLimit
		e.DailyLimit = &dailyLimit
	}

	if e.TransactionLimit == nil {
		transactionLimit := defaultTransactionLimit
		e.TransactionLimit = &transactionLimit
	}

	return s.updateStatus(ctx, e, StatusAwaitingEnrollment)
}

func (s Service) InitRegistration(ctx context.Context, id, orgID string, opts FIDOOptions) (*Enrollment, error) {
	e, err := s.Enrollment(ctx, Query{ID: id, LoadOwner: true, LoadClient: true}, orgID)
	if err != nil {
		return nil, err
	}

	if e.Status != StatusAwaitingEnrollment {
		return nil, errorutil.Format("%w: enrollment is not in awaiting enrollment status", ErrInvalidStatus)
	}

	if opts.RelyingParty != e.RelyingParty {
		reason := RejectionReasonFidoFailure
		_ = s.Cancel(ctx, e, Cancellation{From: payment.CancelledFromHolder, RejectionReason: &reason})
		return nil, errorutil.Format("%w: relying party mismatch", ErrInvalidRelyingParty)
	}

	challenge := generateChallenge()
	e.Challenge = &challenge
	return e, s.update(ctx, e)
}

func (s Service) RegisterCredential(ctx context.Context, id, orgID string, credential Credential) error {
	e, err := s.Enrollment(ctx, Query{ID: id, LoadClient: true}, orgID)
	if err != nil {
		return err
	}

	if e.Status != StatusAwaitingEnrollment {
		return errorutil.New("enrollment is not in awaiting enrollment status")
	}

	data, err := json.Marshal(credential)
	if err != nil {
		return errorutil.Format("%w: invalid credential: %w", ErrInvalidPublicKey, err)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(data))
	if err != nil {
		reason := RejectionReasonFidoFailure
		_ = s.Cancel(ctx, e, Cancellation{From: payment.CancelledFromHolder, RejectionReason: &reason})
		return errorutil.Format("%w: invalid credential: %w", ErrInvalidPublicKey, err)
	}

	if !slices.Contains(e.Client.OriginURIs, parsed.Response.CollectedClientData.Origin) {
		reason := RejectionReasonFidoFailure
		_ = s.Cancel(ctx, e, Cancellation{From: payment.CancelledFromHolder, RejectionReason: &reason})
		return errorutil.Format("%w: invalid credential: %w", ErrInvalidOrigin, err)
	}

	_, err = parsed.Verify(*e.Challenge, true, e.RelyingParty, e.Client.OriginURIs, nil,
		protocol.TopOriginIgnoreVerificationMode, nil, PublicKeyCredentialParameters)
	if err != nil {
		reason := RejectionReasonFidoFailure
		_ = s.Cancel(ctx, e, Cancellation{From: payment.CancelledFromHolder, RejectionReason: &reason})
		return errorutil.Format("%w: invalid credential: %w", ErrInvalidPublicKey, err)
	}

	publicKey := base64.RawStdEncoding.EncodeToString(parsed.Response.AttestationObject.AuthData.AttData.CredentialPublicKey)
	e.PublicKey = &publicKey
	e.Challenge = nil
	return s.updateStatus(ctx, e, StatusAuthorized)
}

func (s Service) InitAuthorization(ctx context.Context, consentID, enrollmentID, orgID string, opts FIDOOptions) (string, error) {
	e, err := s.Enrollment(ctx, Query{ID: enrollmentID, LoadClient: true}, orgID)
	if err != nil {
		return "", err
	}

	if e.Status != StatusAuthorized {
		return "", errorutil.Format("%w: enrollment is not in authorized status", ErrInvalidStatus)
	}

	if opts.RelyingParty != e.RelyingParty {
		return "", errorutil.Format("%w: relying party mismatch", ErrInvalidRelyingParty)
	}

	var enrollConsent func(ctx context.Context, consentID, orgID string, opts payment.EnrollmentOptions) error
	if strings.HasPrefix(consentID, payment.ConsentURNPrefix) {
		enrollConsent = s.paymentService.EnrollConsent
	} else if strings.HasPrefix(consentID, autopayment.ConsentURNPrefix) {
		enrollConsent = s.autopaymentService.EnrollConsent
	} else {
		return "", errorutil.New("invalid consent id")
	}

	challenge := generateChallenge()
	enrollmentOpts := payment.EnrollmentOptions{
		EnrollmentID:           e.ID,
		DebtorAccountID:        e.DebtorAccountID,
		UserIdentification:     e.UserIdentification,
		BusinessIdentification: e.BusinessIdentification,
		Challenge:              challenge,
	}
	if e.TransactionLimit != nil {
		enrollmentOpts.TransactionLimit = *e.TransactionLimit
	}
	if e.DailyLimit != nil {
		enrollmentOpts.DailyLimit = *e.DailyLimit
	}

	return challenge, enrollConsent(ctx, consentID, orgID, enrollmentOpts)
}

func (s Service) AuthorizeConsent(ctx context.Context, consentID, id, orgID string, assertion FIDOAssertion) error {
	e, err := s.Enrollment(ctx, Query{ID: id, LoadClient: true}, orgID)
	if err != nil {
		return err
	}

	if e.Status != StatusAuthorized {
		_ = s.rejectConsent(ctx, consentID, orgID, "enrollment is not in authorized status")
		return errorutil.Format("%w: enrollment is not in authorized status", ErrInvalidStatus)
	}

	data, err := json.Marshal(assertion)
	if err != nil {
		return errorutil.New("invalid assertion")
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(data))
	if err != nil {
		return errorutil.New("invalid assertion")
	}

	publicKey, _ := base64.RawStdEncoding.DecodeString(*e.PublicKey)
	var verify = func(challenge *string) error {
		if challenge == nil {
			return errorutil.New("challenge was not initialized")
		}

		if err := parsed.Verify(*challenge, e.RelyingParty, e.Client.OriginURIs, nil,
			protocol.TopOriginIgnoreVerificationMode, "", true, publicKey); err != nil {
			return errorutil.Format("%w: %w", ErrInvalidAssertion, err)
		}
		return nil
	}

	if strings.HasPrefix(consentID, payment.ConsentURNPrefix) {
		c, err := s.paymentService.Consent(ctx, consentID, orgID)
		if err != nil {
			return err
		}
		if err := verify(c.EnrollmentChallenge); err != nil {
			_ = s.rejectConsent(ctx, consentID, orgID, "error verifying enrollment challenge")
			return err
		}
		return s.paymentService.AuthorizeConsent(ctx, c)
	}
	if strings.HasPrefix(consentID, autopayment.ConsentURNPrefix) {
		c, err := s.autopaymentService.Consent(ctx, consentID, orgID)
		if err != nil {
			return err
		}
		if err := verify(c.EnrollmentChallenge); err != nil {
			_ = s.rejectConsent(ctx, consentID, orgID, "error verifying enrollment challenge")
			return err
		}
		return s.autopaymentService.AuthorizeConsent(ctx, c)
	}

	return errorutil.New("invalid consent ID")
}

func (s Service) rejectConsent(ctx context.Context, id, orgID, detail string) error {
	if strings.HasPrefix(id, payment.ConsentURNPrefix) {
		_, err := s.paymentService.RejectConsentByID(ctx, id, orgID, payment.ConsentRejectionNotProvided, detail)
		return err
	}
	if strings.HasPrefix(id, autopayment.ConsentURNPrefix) {
		_, err := s.autopaymentService.RejectConsentByID(ctx, id, orgID, autopayment.ConsentRejection{
			By:     autopayment.TerminatedByHolder,
			From:   autopayment.TerminatedFromHolder,
			Code:   autopayment.ConsentRejectionNotProvided,
			Detail: detail,
		})
		return err
	}
	return errorutil.New("invalid consent ID")
}

func (s Service) Enrollment(ctx context.Context, query Query, orgID string) (*Enrollment, error) {
	dbQuery := s.db.WithContext(ctx).Where("org_id = ?", orgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", strings.TrimPrefix(query.ID, URNPrefix))
	}
	if query.LoadDebtorAccount {
		dbQuery = dbQuery.Preload("DebtorAccount")
	}
	if query.LoadOwner {
		dbQuery = dbQuery.Preload("Owner")
	}
	if query.LoadClient {
		dbQuery = dbQuery.Preload("Client")
	}

	e := &Enrollment{}
	if err := dbQuery.First(e).Error; err != nil {
		return nil, err
	}

	if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != e.ClientID {
		return nil, ErrClientNotAllowed
	}

	switch e.Status {
	case StatusAwaitingRiskSignals:
		if timeutil.DateTimeNow().After(e.CreatedAt.Add(5 * time.Minute)) {
			reason := RejectionReasonAwaitingRiskSignals
			return e, s.Cancel(ctx, e, Cancellation{RejectionReason: &reason, From: payment.CancelledFromHolder})
		}
	case StatusAwaitingAccountHolderValidation:
		if timeutil.DateTimeNow().After(e.StatusUpdatedAt.Add(15 * time.Minute)) {
			reason := RejectionReasonAwaitingAccountHolderValidation
			return e, s.Cancel(ctx, e, Cancellation{RejectionReason: &reason, From: payment.CancelledFromHolder})
		}
	case StatusAwaitingEnrollment:
		if timeutil.DateTimeNow().After(e.StatusUpdatedAt.Add(CredentialRegistrationTimeout)) {
			reason := RejectionReasonAwaitingEnrollment
			return e, s.Cancel(ctx, e, Cancellation{RejectionReason: &reason, From: payment.CancelledFromHolder})
		}
	}

	return e, nil
}

func (s Service) CancelByID(ctx context.Context, id, orgID string, cancellation Cancellation) error {
	e, err := s.Enrollment(ctx, Query{ID: id}, orgID)
	if err != nil {
		return err
	}
	return s.Cancel(ctx, e, cancellation)
}

func (s Service) Cancel(ctx context.Context, e *Enrollment, cancellation Cancellation) error {
	if e.Status == StatusRejected || e.Status == StatusRevoked {
		return errorutil.New("enrollment is already cancelled")
	}

	status := StatusRejected
	if cancellation.RevocationReason != nil {
		status = StatusRevoked
	}

	if cancellation.From == payment.CancelledFromHolder {
		now := timeutil.DateTimeNow()
		cancellation.At = &now
	}

	e.Cancellation = &cancellation
	return s.updateStatus(ctx, e, status)
}

func (s Service) validate(_ context.Context, e *Enrollment, debtorAccount *payment.Account) error {
	for _, p := range e.Permissions {
		if p != PermissionPaymentsInitiate {
			return errorutil.Format("%w: permission %s is not allowed", ErrInvalidPermissions, p)
		}
	}

	if e.RelyingParty == "" {
		return errorutil.Format("%w: relying party is required", ErrMissingValue)
	}

	if e.UserRel != consent.RelationCPF {
		return errorutil.Format("%w: only CPF is allowed for logged user document relation", ErrInvalidData)
	}

	if e.BusinessRel != nil && *e.BusinessRel != consent.RelationCNPJ {
		return errorutil.Format("%w: only CNPJ is allowed for business document relation", ErrInvalidData)
	}

	if debtorAccount != nil && slices.Contains([]payment.AccountType{
		payment.AccountTypeCACC,
		payment.AccountTypeSVGS,
	}, debtorAccount.Type) && debtorAccount.Issuer == nil {
		return errorutil.Format("%w: debtor account issuer is required for account types CACC or SVGS", ErrMissingValue)
	}

	return nil
}

func (s Service) updateStatus(ctx context.Context, e *Enrollment, status Status) error {
	e.Status = status
	e.StatusUpdatedAt = timeutil.DateTimeNow()
	if err := s.update(ctx, e); err != nil {
		return fmt.Errorf("could not update enrollment status: %w", err)
	}

	if slices.Contains([]Status{StatusRejected, StatusRevoked}, status) {
		s.webhookService.NotifyEnrollment(ctx, e.ClientID, e.URN(), e.Version)
	}

	return nil
}

func (s Service) update(ctx context.Context, e *Enrollment) error {
	e.UpdatedAt = timeutil.DateTimeNow()
	if err := s.db.WithContext(ctx).
		Model(&Enrollment{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", e.ID, e.OrgID).
		Updates(e).Error; err != nil {
		return fmt.Errorf("could not update enrollment: %w", err)
	}
	return nil
}
