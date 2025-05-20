package app

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/timeutil"
)

type ContextKey string

const (
	CtxKeyOrgID         ContextKey = "org_id"
	CtxKeySessionID     ContextKey = "session_id"
	CtxKeyInteractionID ContextKey = "interaction_id"
)

const (
	cookieSessionId = "sessionId"
	cookieNonce     = "nonce"
	sessionValidity = 24 * time.Hour
	nonceValidity   = 15 * time.Minute
)

type Session struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username      string
	Organizations Organizations `gorm:"type:jsonb"`

	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timeutil.Now())
}

type Organizations map[string]struct {
	Name string `json:"name"`
}

func (o Organizations) Value() (driver.Value, error) {
	return json.Marshal(o)
}

func (o *Organizations) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to convert value to []byte")
	}
	return json.Unmarshal(bytes, o)
}

type directoryIDToken struct {
	Sub     string `json:"sub"`
	Nonce   string `json:"nonce"`
	Profile struct {
		OrgAccessDetails map[string]struct {
			Name    string `json:"organisation_name"`
			IsAdmin bool   `json:"org_admin"`
		} `json:"org_access_details"`
	} `json:"trust_framework_profile"`
}

type directoryWellKnown struct {
	AuthEndpoint       string                    `json:"authorization_endpoint"`
	PushedAuthEndpoint string                    `json:"pushed_authorization_request_endpoint"`
	JWKSURI            string                    `json:"jwks_uri"`
	IDTokenSigAlgs     []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
}
