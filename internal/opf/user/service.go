package user

import (
	"context"
	"errors"

	"github.com/luiky/mock-bank/internal/page"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{
		db: db,
	}
}

func (s Service) Create(ctx context.Context, u *User) error {
	if err := s.db.WithContext(ctx).Create(u).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (s Service) User(ctx context.Context, id, orgID string) (*User, error) {
	u := &User{}
	err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).First(u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s Service) UserByCPF(ctx context.Context, cpf, orgID string) (*User, error) {
	u := &User{}
	err := s.db.WithContext(ctx).Where("cpf = ? AND org_id = ?", cpf, orgID).First(u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s Service) UserByUsername(ctx context.Context, username, orgID string) (*User, error) {
	u := &User{}
	err := s.db.WithContext(ctx).Where("username = ? AND org_id = ?", username, orgID).First(u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s Service) Users(ctx context.Context, orgID string, pag page.Pagination) (page.Page[*User], error) {
	query := s.db.WithContext(ctx).Model(&User{}).Where("org_id = ?", orgID)

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

func (s Service) Delete(ctx context.Context, id, orgID string) error {
	return s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).Delete(&User{}).Error
}
