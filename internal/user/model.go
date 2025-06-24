package user

import (
	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type User struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username    string
	Name        string
	CPF         string
	Description string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (User) TableName() string {
	return "mock_users"
}

type Query struct {
	ID       string
	Username string
	CPF      string
}

type Company struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Name        string
	CNPJ        string
	Description string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Company) TableName() string {
	return "mock_companies"
}
