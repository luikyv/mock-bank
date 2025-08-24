package creditportability

import (
	"context"
	"errors"
	"fmt"

	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db              *gorm.DB
	creditopService *creditop.Service
}

func NewService(db *gorm.DB, creditopService *creditop.Service) *Service {
	return &Service{db: db, creditopService: creditopService}
}

func (s *Service) AccountData(ctx context.Context, portabilityID string) (*AccountData, error) {
	return &AccountData{
		Number: "12345678",
	}, nil
}

func (s *Service) Eligibility(ctx context.Context, contractID, consentID, orgID string) (*Eligibility, error) {

	if _, err := s.creditopService.ConsentedContract(ctx, contractID, consentID, orgID, resource.TypeLoan); err != nil {
		return nil, err
	}

	eligibility := &Eligibility{}
	if err := s.db.WithContext(ctx).
		Where(`contract_id = ? AND org_id = ?`, contractID, orgID).
		First(eligibility).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			reason := IneligibilityReasonOther
			additionalInfo := "Eligibility not defined for this contract"
			return &Eligibility{
				IsEligible:                        false,
				IneligibilityReason:               &reason,
				IneligibilityReasonAdditionalInfo: &additionalInfo,
			}, nil
		}
		return nil, fmt.Errorf("could not fetch eligibility: %w", err)
	}

	return eligibility, nil
}

func (s *Service) Create(ctx context.Context, portability *Portability) error {
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
