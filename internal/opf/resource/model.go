package resource

import (
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	Scope = goidc.NewScope("resources")
)

type Status string

const (
	StatusAvailable            Status = "AVAILABLE"
	StatusUnavailable          Status = "UNAVAILABLE"
	StatusPendingAuthorization Status = "PENDING_AUTHORISATION"
)

type Type string

const (
	TypeAccount Type = "ACCOUNT"
)

type Resource struct {
	ConsentID  string
	ResourceID string
	Status     Status
	Type       Type `gorm:"column:resource_type"`

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Resource) TableName() string {
	return "consent_resources"
}
