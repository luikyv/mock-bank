package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username    string
	Name        string
	CPF         string
	Description string

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (User) TableName() string {
	return "mock_users"
}
