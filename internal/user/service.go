package user

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/page"
	"gorm.io/gorm"
)

type Service struct {
	db        *gorm.DB
	mockOrgID string
}

func NewService(db *gorm.DB, mockOrgID string) Service {
	return Service{db: db, mockOrgID: mockOrgID}
}

func (s Service) Save(ctx context.Context, u *User) error {
	if err := s.db.WithContext(ctx).Save(u).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (s Service) User(ctx context.Context, query Query, orgID string) (*User, error) {
	u := &User{}
	dbQuery := s.db.WithContext(ctx).Where("org_id = ? OR org_id = ?", orgID, s.mockOrgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", query.ID)
	}
	if query.CPF != "" {
		dbQuery = dbQuery.Where("cpf = ?", query.CPF)
	}
	if query.Username != "" {
		dbQuery = dbQuery.Where("username = ?", query.Username)
	}

	if err := dbQuery.First(u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

func (s Service) Users(ctx context.Context, orgID string, pag page.Pagination) (page.Page[*User], error) {
	query := s.db.WithContext(ctx).Model(&User{}).Where("org_id = ? OR org_id = ?", orgID, s.mockOrgID)

	var users []*User
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&users).Error; err != nil {
		return page.Page[*User]{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*User]{}, err
	}

	return page.New(users, pag, int(total)), nil
}

func (s Service) Delete(ctx context.Context, id uuid.UUID, orgID string) error {
	return s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).Delete(&User{}).Error
}
