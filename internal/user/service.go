package user

import (
	"context"
	"errors"

	"gorm.io/gorm/clause"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db        *gorm.DB
	mockOrgID string
}

func NewService(db *gorm.DB, mockOrgID string) Service {
	return Service{db: db, mockOrgID: mockOrgID}
}

func (s Service) Create(ctx context.Context, u *User) error {
	u.CreatedAt = timeutil.DateTimeNow()
	u.UpdatedAt = timeutil.DateTimeNow()
	if err := s.db.WithContext(ctx).Create(u).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (s Service) Update(ctx context.Context, u *User) error {
	u.UpdatedAt = timeutil.DateTimeNow()
	tx := s.db.WithContext(ctx).
		Model(&User{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ?", u.ID).
		Updates(u)
	if err := tx.Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrAlreadyExists
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return err
	}

	return nil
}

func (s Service) User(ctx context.Context, query Query, orgID string) (*User, error) {
	u := &User{}
	dbQuery := s.db.WithContext(ctx).Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID)
	if query.ID != "" {
		dbQuery = dbQuery.Where("id = ?", query.ID)
	}
	if query.CPF != "" {
		dbQuery = dbQuery.Where("cpf = ?", query.CPF)
	}
	if query.Username != "" {
		dbQuery = dbQuery.Where("username = ?", query.Username)
	}
	if query.CNPJ != "" {
		dbQuery = dbQuery.Where("cnpj = ?", query.CNPJ)
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
	query := s.db.WithContext(ctx).Model(&User{}).Where("org_id = ? OR (org_id = ? AND cross_org = true)", orgID, s.mockOrgID)

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

// Business retrieves and returns the business user entity associated with the specified user ID and CNPJ.
// It performs access control validation to ensure the user has permission to access the requested business.
func (s Service) Business(ctx context.Context, userID, cnpj, orgID string) (*User, error) {
	business, err := s.User(ctx, Query{CNPJ: cnpj}, orgID)
	if err != nil {
		return nil, err
	}

	if business.ID.String() == userID {
		return business, nil
	}

	err = s.db.WithContext(ctx).
		Where("user_id = ? AND business_user_id = ? AND org_id = ?", userID, business.ID, business.OrgID).
		First(&UserBusiness{}).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserDoesNotOwnBusiness
		}
		return nil, err
	}

	return business, nil
}

func (s Service) BindUserToBusiness(ctx context.Context, userID, businessID uuid.UUID, orgID string) error {
	business, err := s.User(ctx, Query{ID: businessID.String()}, orgID)
	if err != nil {
		return err
	}
	if business.OrgID != orgID {
		return ErrInvalidOrgID
	}
	// TODO: check if business is a company.

	user, err := s.User(ctx, Query{ID: userID.String()}, orgID)
	if err != nil {
		return err
	}
	if user.OrgID != orgID {
		return ErrInvalidOrgID
	}

	userBusiness := &UserBusiness{
		UserID:         userID,
		BusinessUserID: business.ID,
		OrgID:          orgID,
	}
	if err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "business_user_id"}},
			DoNothing: true,
		}).
		Create(userBusiness).Error; err != nil {
		return err
	}
	return nil
}
