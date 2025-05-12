package app

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/timex"
)

const (
	cookieSessionId = "sessionId"
	sessionValidity = 24 * time.Hour
)

type Session struct {
	ID            uuid.UUID `gorm:"primaryKey"`
	Username      string
	Organizations Organizations `gorm:"column:organizations;type:jsonb;not null"`

	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timex.Now())
}

type Organizations map[string]struct {
	Name string `json:"name"`
}

func (o Organizations) Value() (driver.Value, error) {
	return json.Marshal(o)
}

func (o *Organizations) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to convert value to []byte")
	}
	return json.Unmarshal(bytes, o)
}

type directoryIDToken struct {
	Sub     string `json:"sub"`
	Profile struct {
		OrgAccessDetails map[string]struct {
			Name    string `json:"organisation_name"`
			IsAdmin bool   `json:"org_admin"`
		} `json:"org_access_details"`
	} `json:"trust_framework_profile"`
}

type directoryWellKnown struct {
	AuthEndpoint   string                    `json:"authorization_endpoint"`
	JWKSURI        string                    `json:"jwks_uri"`
	IDTokenSigAlgs []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
}
