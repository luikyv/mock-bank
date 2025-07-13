package customer

import (
	"context"
	"fmt"

	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/page"
	"gorm.io/gorm"
)

type Service struct {
	db             *gorm.DB
	accountService *account.Service
	mockOrgID      string
}

func NewService(db *gorm.DB, accountService *account.Service) *Service {
	return &Service{db: db, accountService: accountService}
}

func (s *Service) PersonalIdentifications(ctx context.Context, ownerID, orgID string, pag page.Pagination) (page.Page[*PersonalIdentification], error) {
	query := s.db.WithContext(ctx).
		Model(&PersonalIdentification{}).
		Where(`owner_id = ?`, ownerID).
		Where(`org_id = ? OR (org_id = ? AND cross_org = true)`, orgID, s.mockOrgID).
		Order("created_at DESC")

	return page.Paginate[*PersonalIdentification](query, pag)
}

func (s *Service) ConsentedPersonalIdentifications(ctx context.Context, ownerID, orgID string, pag page.Pagination) (page.Page[*PersonalIdentification], error) {
	return s.PersonalIdentifications(ctx, ownerID, orgID, pag)
}

func (s *Service) PersonalQualification(ctx context.Context, ownerID, orgID string) (*PersonalQualification, error) {
	qualification := &PersonalQualification{}
	if err := s.db.WithContext(ctx).
		Model(&PersonalQualification{}).
		Where(`owner_id = ?`, ownerID).
		Where(`org_id = ? OR (org_id = ? AND cross_org = true)`, orgID, s.mockOrgID).
		First(qualification).Error; err != nil {
		return nil, fmt.Errorf("failed to find personal qualification: %w", err)
	}

	return qualification, nil
}

func (s *Service) ConsentedPersonalQualification(ctx context.Context, ownerID, orgID string) (*PersonalQualification, error) {
	return s.PersonalQualification(ctx, ownerID, orgID)
}

func (s *Service) PersonalFinancialRelation(ctx context.Context, ownerID, orgID string) (*PersonalFinancialRelation, error) {
	relation := &PersonalFinancialRelation{}
	if err := s.db.WithContext(ctx).
		Where(`owner_id = ?`, ownerID).
		Where(`org_id = ? OR (org_id = ? AND cross_org = true)`, orgID, s.mockOrgID).
		First(relation).Error; err != nil {
		return nil, fmt.Errorf("failed to find personal financial relation: %w", err)
	}

	return relation, nil
}

func (s *Service) ConsentedPersonalFinancialRelation(ctx context.Context, ownerID, orgID string) (*PersonalFinancialRelation, error) {
	return s.PersonalFinancialRelation(ctx, ownerID, orgID)
}
