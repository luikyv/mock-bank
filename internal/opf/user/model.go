package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID       uuid.UUID `gorm:"primaryKey"`
	Username string
	Name     string
	CPF      string

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (User) TableName() string {
	return "mock_users"
}
