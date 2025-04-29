package auth

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luiky/mock-bank/internal/timex"
)

const (
	cookieSessionId = "session_id"
)

type Session struct {
	ID            string                  `bson:"_id"`
	Username      string                  `bson:"username"`
	Organizations map[string]Organization `bson:"organizations"`
	CreatedAt     timex.DateTime          `bson:"created_at"`
	ExpiresAt     timex.DateTime          `bson:"expires_at"`
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timex.Now())
}

type Organization struct {
	Name string `bson:"name"`
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
