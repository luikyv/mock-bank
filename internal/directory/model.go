package directory

import "github.com/go-jose/go-jose/v4"

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

type directoryWellKnown struct {
	AuthEndpoint       string                    `json:"authorization_endpoint"`
	PushedAuthEndpoint string                    `json:"pushed_authorization_request_endpoint"`
	JWKSURI            string                    `json:"jwks_uri"`
	IDTokenSigAlgs     []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
}
