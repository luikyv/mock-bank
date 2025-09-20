package creditportability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	storage         storage
	creditopService creditop.Service
}

func NewService(db *gorm.DB, creditopService creditop.Service) Service {
	return Service{storage: storage{db: db}, creditopService: creditopService}
}

func (s Service) AccountData(ctx context.Context, portabilityID string) (*AccountData, error) {
	return &AccountData{
		Number: "12345678",
	}, nil
}

func (s Service) Eligibility(ctx context.Context, contractID, consentID, orgID string) (*Eligibility, error) {
	_, eligibility, err := s.eligibility(ctx, contractID, consentID, orgID)
	return eligibility, err
}

func (s Service) eligibility(ctx context.Context, contractID, consentID, orgID string) (*creditop.Contract, *Eligibility, error) {
	contract, err := s.creditopService.ConsentedContract(ctx, contractID, consentID, orgID)
	if err != nil {
		return nil, nil, err
	}

	eligibility, err := s.storage.eligibility(ctx, contractID, orgID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			reason := IneligibilityReasonOther
			reasonAdditionalInfo := "portability eligibility not found for contract"
			return contract, &Eligibility{
				ContractID:                        contract.ID,
				IsEligible:                        false,
				IneligibilityReason:               &reason,
				IneligibilityReasonAdditionalInfo: &reasonAdditionalInfo,
			}, nil
		}
		return nil, nil, err
	}

	return contract, eligibility, nil
}

func (s Service) Create(ctx context.Context, portability *Portability) error {
	contract, eligibility, err := s.eligibility(ctx, portability.ContractID.String(), portability.ConsentID.String(), portability.OrgID)
	if err != nil {
		return err
	}

	if !eligibility.IsEligible {
		return ErrContractNotEligible
	}

	if eligibility.Status == nil || *eligibility.Status != EligibilityStatusAvailable {
		return ErrPortabilityInProgress
	}

	if portability.CreditorInstitutionCNPJ != contract.CompanyCNPJ {
		return errorutil.Format("%w: the informed creditor institution CNPJ is not the same as the contract company CNPJ", ErrIncompatibleInformation)
	}

	if portability.ProposedInstalmentPeriodicity != contract.InstalmentPeriodicity {
		return ErrIncompatibleInstalmentPeriodicity
	}

	if portability.ProposedTotalInstalments > contract.DueInstalments {
		return ErrInstalmentTermOverLimit
	}

	if payment.ConvertAmount(portability.ProposedAmount) > payment.ConvertAmount(contract.OutstandingBalance) {
		return ErrProposedAmountOverLimit
	}

	portability.Status = StatusReceived
	portability.StatusUpdatedAt = timeutil.DateTimeNow()
	portability.CreatedAt = timeutil.DateTimeNow()
	portability.UpdatedAt = timeutil.DateTimeNow()
	if err := s.storage.create(ctx, portability); err != nil {
		return err
	}

	go func() {

		run := func(ctx context.Context, portability *Portability) error {
			switch portability.Status {
			case StatusReceived:
				return s.updateStatus(ctx, portability, StatusAcceptedSettlementInProgress)
			}
			return nil
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				portability, err := s.Portability(ctx, Query{ID: portability.ID.String()}, portability.OrgID)
				if err != nil {
					slog.ErrorContext(ctx, "error loading portability for automation", "id", portability.ID, "error", err)
					return
				}

				if err := run(ctx, portability); err != nil {
					slog.ErrorContext(ctx, "error running portability automations", "id", portability.ID, "error", err)
					return
				}

				if portability.Status != StatusReceived {
					slog.DebugContext(ctx, "automation completed, stopping ticker", "id", portability.ID)
					return
				}
			case <-ctx.Done():
				slog.DebugContext(ctx, "automation deadline reached, stopping ticker", "id", portability.ID)
				return
			}
		}
	}()

	return nil
}

func (s Service) Portability(ctx context.Context, query Query, orgID string) (*Portability, error) {
	portability, err := s.storage.portability(ctx, query, orgID)
	if err != nil {
		return nil, err
	}

	if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != portability.ClientID {
		return nil, ErrClientNotAllowed
	}

	return portability, nil
}

func (s Service) CreatePayment(ctx context.Context, portabilityID, orgID string, pay Payment) (*Portability, error) {
	portability, err := s.Portability(ctx, Query{ID: portabilityID, LoadContract: true}, orgID)
	if err != nil {
		return nil, err
	}

	if portability.Status != StatusAcceptedSettlementInProgress {
		return nil, ErrPortabilityNotAcceptedSettlementInProgress
	}

	portability.Payment = &pay
	if err := s.updateStatus(ctx, portability, StatusAcceptedSettlementCompleted); err != nil {
		return nil, fmt.Errorf("could not update portability for payment submission: %w", err)
	}

	go func() {

		run := func(ctx context.Context, portability *Portability) error {
			if payment.ConvertAmount(portability.Payment.Amount) < payment.ConvertAmount(portability.Contract.OutstandingBalance) {
				reason := RejectionReasonPaymentDiscrepancy
				reasonAdditionalInfo := "payment amount is less than outstanding balance"
				portability.StatusReason = &StatusReason{
					ReasonType:               &reason,
					ReasonTypeAdditionalInfo: &reasonAdditionalInfo,
				}
				if err := s.updateStatus(ctx, portability, StatusPaymentIssue); err != nil {
					return fmt.Errorf("could not update portability for payment submission: %w", err)
				}
				return nil
			}

			portability.LoanSettlementInstruction = &SettlementInstruction{
				Amount:        portability.Payment.Amount,
				Currency:      portability.Payment.Currency,
				DateTime:      timeutil.DateTimeNow(),
				TransactionID: portability.Payment.TransactionID,
			}
			if err := s.updateStatus(ctx, portability, StatusPortabilityCompleted); err != nil {
				return fmt.Errorf("could not update portability for payment submission: %w", err)
			}
			return nil
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				portability, err := s.Portability(ctx, Query{ID: portability.ID.String(), LoadContract: true}, portability.OrgID)
				if err != nil {
					slog.ErrorContext(ctx, "error loading portability for payment automation", "id", portability.ID, "error", err)
					return
				}

				if err := run(ctx, portability); err != nil {
					slog.ErrorContext(ctx, "error running portability payment automation", "id", portability.ID, "error", err)
					return
				}

				if portability.Status != StatusAcceptedSettlementCompleted {
					slog.DebugContext(ctx, "payment automation completed, stopping ticker", "id", portability.ID)
					return
				}
			case <-ctx.Done():
				slog.DebugContext(ctx, "payment automation deadline reached, stopping ticker", "id", portability.ID)
				return
			}
		}
	}()

	return portability, nil
}

func (s Service) Cancel(ctx context.Context, portabilityID, orgID string, rejection Rejection) (*Portability, error) {
	portability, err := s.Portability(ctx, Query{ID: portabilityID}, orgID)
	if err != nil {
		return nil, err
	}

	if !slices.Contains([]Status{
		StatusReceived,
		StatusPending,
		StatusAcceptedSettlementInProgress,
	}, portability.Status) {
		return nil, errorutil.Format("%w: portability in status %s cannot be cancelled", ErrCancelNotAllowed, portability.Status)
	}

	portability.Status = StatusCancelled
	portability.StatusUpdatedAt = timeutil.DateTimeNow()
	portability.Rejection = &rejection
	statusReason := RejectionReasonCanceledByClient
	statusReasonAdditionalInfo := "portability cancelled by client"
	portability.StatusReason = &StatusReason{
		ReasonType:               &statusReason,
		ReasonTypeAdditionalInfo: &statusReasonAdditionalInfo,
	}
	return portability, s.update(ctx, portability)
}

func (s Service) Reject(ctx context.Context, portabilityID, orgID string, rejection Rejection) error {
	portability, err := s.Portability(ctx, Query{ID: portabilityID}, orgID)
	if err != nil {
		return err
	}

	portability.Status = StatusRejected
	portability.StatusUpdatedAt = timeutil.DateTimeNow()
	portability.Rejection = &rejection
	return s.update(ctx, portability)
}

func (s Service) updateStatus(ctx context.Context, portability *Portability, status Status) error {
	portability.Status = status
	portability.StatusUpdatedAt = timeutil.DateTimeNow()
	return s.update(ctx, portability)
}

func (s Service) update(ctx context.Context, portability *Portability) error {
	portability.UpdatedAt = timeutil.DateTimeNow()
	return s.storage.update(ctx, portability)
}
