package resource

import (
	"github.com/google/uuid"
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
	ID         uuid.UUID `gorm:"primaryKey"`
	ConsentID  uuid.UUID
	ResourceID uuid.UUID
	Status     Status
	Type       Type
}

func (Resource) TableName() string {
	return "consent_resources"
}
