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
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	ConsentID  string
	ResourceID string
	Status     Status
	Type       Type
}

func (Resource) TableName() string {
	return "consent_resources"
}

func New(resourceID, consentID string, status Status, resourceType Type) *Resource {
	return &Resource{
		ResourceID: resourceID,
		ConsentID:  consentID,
		Status:     status,
		Type:       resourceType,
	}
}
