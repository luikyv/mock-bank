package session

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type Session struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username      string
	Organizations Organizations `gorm:"serializer:json"`
	CodeVerifier  string

	CreatedAt timeutil.DateTime
	ExpiresAt timeutil.DateTime
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timeutil.DateTimeNow())
}

type Organizations map[string]struct {
	Name string `json:"name"`
}

type IDToken struct {
	Sub     string `json:"sub"`
	Nonce   string `json:"nonce"`
	Profile struct {
		OrgAccessDetails map[string]struct {
			Name    string `json:"organisation_name"`
			IsAdmin bool   `json:"org_admin"`
		} `json:"org_access_details"`
	} `json:"trust_framework_profile"`
}

type openIDConfiguration struct {
	AuthEndpoint   string                    `json:"authorization_endpoint"`
	JWKSURI        string                    `json:"jwks_uri"`
	TokenEndpoint  string                    `json:"token_endpoint"`
	IDTokenSigAlgs []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
	MTLS           struct {
		PushedAuthEndpoint string `json:"pushed_authorization_request_endpoint"`
		TokenEndpoint      string `json:"token_endpoint"`
	} `json:"mtls_endpoint_aliases"`
}
