package idempotency

import "time"

type Record struct {
	ID         string `gorm:"primaryKey"`
	StatusCode int
	Request    string
	Response   string

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Record) TableName() string {
	return "idempotency_records"
}
