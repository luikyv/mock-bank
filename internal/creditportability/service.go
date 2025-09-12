package creditportability

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db              *gorm.DB
	creditopService creditop.Service
}

func NewService(db *gorm.DB, creditopService creditop.Service) Service {
	return Service{db: db, creditopService: creditopService}
}

func (s Service) AccountData(ctx context.Context, portabilityID string) (*AccountData, error) {
	return &AccountData{
		Number: "12345678",
	}, nil
}

func (s Service) Eligibility(ctx context.Context, contractID, consentID, orgID string) (*Eligibility, error) {

	contract, err := s.creditopService.ConsentedContract(ctx, contractID, consentID, orgID, resource.TypeLoan)
	if err != nil {
		return nil, err
	}

	if !contract.PortabilityIsEligible {
		return &Eligibility{
			ContractID:                        contractID,
			IsEligible:                        false,
			IneligibilityReason:               contract.PortabilityIneligibleReason,
			IneligibilityReasonAdditionalInfo: contract.PortabilityIneligibleReasonAdditionalInfo,
		}, nil
	}

	portability, err := s.Portability(ctx, contractID)
	if err != nil {
		return nil, err
	}

	if slices.Contains([]Status{StatusRejected, StatusCancelled}, portability.Status) {
		status := EligibilityStatusAvailable
		return &Eligibility{
			ContractID:      contractID,
			IsEligible:      true,
			StatusUpdatedAt: &contract.UpdatedAt,
			Status:          &status,
		}, nil
	}

	status := EligibilityStatusInProgress
	channel := ChannelOFB
	return &Eligibility{
		ContractID:      contractID,
		IsEligible:      true,
		StatusUpdatedAt: &portability.StatusUpdatedAt,
		Status:          &status,
		Channel:         &channel,
		CompanyName:     &portability.InstitutionName,
		CompanyCNPJ:     &portability.InstitutionCNPJ,
	}, nil
}

func (s Service) Create(ctx context.Context, portability *Portability) error {
	eligibility, err := s.Eligibility(ctx, portability.ContractID.String(), portability.ConsentID.String(), portability.OrgID)
	if err != nil {
		return err
	}

	if !eligibility.IsEligible {
		return fmt.Errorf("contract is not eligible for portability")
	}

	if eligibility.Status == nil || *eligibility.Status != EligibilityStatusAvailable {
		return fmt.Errorf("contract is not eligible for portability")
	}

	portability.Status = StatusReceived
	portability.StatusUpdatedAt = timeutil.DateTimeNow()
	portability.CreatedAt = timeutil.DateTimeNow()
	portability.UpdatedAt = timeutil.DateTimeNow()
	if err := s.db.WithContext(ctx).Create(portability).Error; err != nil {
		return fmt.Errorf("could not create portability: %w", err)
	}
	return nil
}

func (s Service) Portability(ctx context.Context, id string) (*Portability, error) {
	portability := &Portability{}
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(portability).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if clientID := ctx.Value(api.CtxKeyClientID); clientID != nil && clientID != portability.ClientID {
		return nil, ErrClientNotAllowed
	}

	return portability, nil
}
