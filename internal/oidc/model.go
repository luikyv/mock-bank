package oidc

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	ACROpenBankingLOA2 goidc.ACR = "urn:brasil:openbanking:loa2"
	ACROpenBankingLOA3 goidc.ACR = "urn:brasil:openbanking:loa3"
)

const (
	OrgIDKey = "org_id"
)

type SoftwareStatement struct {
	SoftwareJWKSInactiveURI string   `json:"software_jwks_inactive_uri"`
	SoftwareMode            string   `json:"software_mode"`
	SoftwareRedirectURIs    []string `json:"software_redirect_uris"`
	SoftwareStatementRoles  []struct {
		Role                string `json:"role"`
		AuthorisationDomain string `json:"authorisation_domain"`
		Status              string `json:"status"`
	} `json:"software_statement_roles"`
	OrgJWKSURI                       string   `json:"org_jwks_uri"`
	OrgJWKSInactiveURI               string   `json:"org_jwks_inactive_uri"`
	OrgJWKSTransportURI              string   `json:"org_jwks_transport_uri"`
	OrgJWKSTransportInactiveURI      string   `json:"org_jwks_transport_inactive_uri"`
	SoftwareJWKSTransportInactiveURI string   `json:"software_jwks_transport_inactive_uri"`
	SoftwareJWKSTransportURI         string   `json:"software_jwks_transport_uri"`
	SoftwareClientName               string   `json:"software_client_name"`
	SoftwareClientID                 string   `json:"software_client_id"`
	SoftwareClientURI                string   `json:"software_client_uri"`
	SoftwareEnvironment              string   `json:"software_environment"`
	SoftwareHomepageURI              string   `json:"software_homepage_uri"`
	SoftwareID                       string   `json:"software_id"`
	SoftwareJWKSURI                  string   `json:"software_jwks_uri"`
	SoftwareLogoURI                  string   `json:"software_logo_uri"`
	SoftwareOriginURIs               []string `json:"software_origin_uris"`
	SoftwareStatus                   string   `json:"software_status"`
	SoftwareVersion                  string   `json:"software_version"`
	SoftwareAPIWebhookURIs           []string `json:"software_api_webhook_uris"`
	SoftwareSectorIdentifierURI      string   `json:"software_sector_identifier_uri"`
	SoftwareRoles                    []string `json:"software_roles"`
	OrgName                          string   `json:"org_name"`
	OrgID                            string   `json:"org_id"`
	OrgNumber                        string   `json:"org_number"`
	OrgStatus                        string   `json:"org_status"`
	OrganisationFlags                struct {
		Generated []string `json:"generated"`
	} `json:"organisation_flags"`
	OrganisationCompetentAuthorityClaims []struct {
		AuthorisationDomain string `json:"authorisation_domain"`
		Authorisations      []any  `json:"authorisations"`
		RegistrationID      string `json:"registration_id"`
		AuthorityName       string `json:"authority_name"`
		AuthorityID         string `json:"authority_id"`
		AuthorisationRole   string `json:"authorisation_role"`
		AuthorityCode       string `json:"authority_code"`
		Status              string `json:"status"`
	} `json:"organisation_competent_authority_claims"`
	SoftwareFlags map[string]any `json:"software_flags"`
	Iss           string         `json:"iss"`
	Iat           int64          `json:"iat"`
}
