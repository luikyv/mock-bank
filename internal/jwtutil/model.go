package jwtutil

import "github.com/luikyv/mock-bank/internal/timeutil"

type JTI struct {
	ID string `gorm:"primaryKey"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (JTI) TableName() string {
	return "jwt_ids"
}
