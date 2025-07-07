package schedule

import (
	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type Schedule struct {
	ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	TaskType  TaskType
	NextRunAt timeutil.DateTime

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

type TaskType string

const (
	TaskTypePayment            TaskType = "PAYMENT"
	TaskTypePaymentConsent     TaskType = "PAYMENT_CONSENT"
	TaskTypeEnrollment         TaskType = "ENROLLMENT"
	TaskTypeAutoPayment        TaskType = "AUTO_PAYMENT"
	TaskTypeAutoPaymentConsent TaskType = "AUTO_PAYMENT_CONSENT"
)
