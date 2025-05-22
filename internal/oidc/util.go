package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"gorm.io/datatypes"
)

const (
	HeaderClientCert = "X-Client-Cert"
	oidUID           = "2.5.4.45"
)

var (
	ssJWKcacheTime      = 1 * time.Hour
	ssJWKSMu            sync.Mutex
	ssJWKSCache         *goidc.JSONWebKeySet
	ssJWKSLastFetchedAt time.Time
)

func TokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(goidc.PS256, 300)
	}
}

func HandleGrantFunc(op *provider.Provider, consentService consent.Service) goidc.HandleGrantFunc {
	return func(r *http.Request, gi *goidc.GrantInfo) error {
		if gi.AdditionalTokenClaims == nil {
			gi.AdditionalTokenClaims = make(map[string]any)
		}
		client, err := op.Client(r.Context(), gi.ClientID)
		if err != nil {
			return fmt.Errorf("could not get client for verifying grant: %w", err)
		}

		orgID := client.CustomAttribute("org_id").(string)
		gi.AdditionalTokenClaims["org_id"] = orgID

		consentID, ok := consent.IDFromScopes(gi.ActiveScopes)
		if !ok {
			return nil
		}

		consent, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch consent for verifying grant: %w", err)
		}

		if !consent.IsAuthorized() {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "consent is not authorized")
		}

		return nil
	}
}

func ShoudIssueRefreshToken(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
	return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) &&
		(grantInfo.GrantType == goidc.GrantAuthorizationCode || grantInfo.GrantType == goidc.GrantRefreshToken)
}

func ClientCert(r *http.Request) (*x509.Certificate, error) {
	rawClientCert := r.Header.Get(HeaderClientCert)
	if rawClientCert == "" {
		return nil, errors.New("the client certificate was not informed")
	}

	// Apply URL decoding.
	rawClientCert, err := url.QueryUnescape(rawClientCert)
	if err != nil {
		return nil, fmt.Errorf("could not url decode the client certificate: %w", err)
	}

	clientCertPEM, _ := pem.Decode([]byte(rawClientCert))
	if clientCertPEM == nil {
		return nil, errors.New("could not decode the client certificate")
	}

	clientCert, err := x509.ParseCertificate(clientCertPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse the client certificate: %w", err)
	}

	return clientCert, nil
}

func LogError(ctx context.Context, err error) {
	slog.InfoContext(ctx, "error during request", slog.String("error", err.Error()))
}

type DCRConfig struct {
	Scopes     []goidc.Scope
	SSURL      string
	SSIssuer   string
	HTTPClient *http.Client
}

func DCRFunc(config DCRConfig) goidc.HandleDynamicClientFunc {
	var scopeIDs []string
	for _, scope := range config.Scopes {
		scopeIDs = append(scopeIDs, scope.ID)
	}

	return func(r *http.Request, _ string, c *goidc.ClientMeta) error {
		clientCert, err := ClientCert(r)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "certificate not informed", err)
		}

		ssa, ok := c.CustomAttribute("software_statement").(string)
		if !ok || ssa == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "software statement is required")
		}

		jwks, err := fetchSoftwareStatementJWKS(config.SSURL, config.HTTPClient)
		if err != nil {
			return goidc.NewError(goidc.ErrorCodeInternalError, "could not fetch the keystore jwks")
		}

		parsedSsa, err := jwt.ParseSigned(ssa, []jose.SignatureAlgorithm{goidc.PS256})
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement", err)
		}

		var claims jwt.Claims
		var ss SoftwareStatement
		if err := parsedSsa.Claims(jwks.ToJOSE(), &claims, &ss); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement signature", err)
		}

		if claims.IssuedAt == nil || timeutil.Now().After(claims.IssuedAt.Time().Add(5*time.Minute)) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement iat claim")
		}

		if err := claims.Validate(jwt.Expected{
			Issuer: config.SSIssuer,
		}); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement claims", err)
		}

		if extractUID(clientCert) != ss.SoftwareID && clientCert.Subject.CommonName != ss.SoftwareID {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement, software id doesn't match certificate cn nor uid")
		}

		if ss.OrgStatus != "Active" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement, organization is not active")
		}

		if len(ss.SoftwareRoles) == 0 {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement, no regulatory roles defined")
		}

		if c.CustomAttribute("software_id") != nil && c.CustomAttribute("software_id") != ss.SoftwareID {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "software id mismatch")
		}

		if c.CustomAttribute("org_id") != nil && c.CustomAttribute("org_id") != ss.OrgID {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "organization id mismatch")
		}

		if c.PublicJWKSURI != ss.SoftwareJWKSURI {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "jwks uri mismatch")
		}

		for _, ru := range c.RedirectURIs {
			if !slices.Contains(ss.SoftwareRedirectURIs, ru) {
				return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "redirect uri not allowed")
			}
		}

		if c.PublicJWKS != nil {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "jwks cannot be informed by value")
		}

		if c.ScopeIDs == "" {
			c.ScopeIDs = strings.Join(scopeIDs, " ")
		}

		c.CustomAttributes = map[string]any{
			"org_id":      ss.OrgID,
			"software_id": ss.SoftwareID,
		}
		return nil
	}
}

func extractUID(cert *x509.Certificate) string {
	for _, name := range cert.Subject.Names {
		if name.Type.String() == oidUID {
			return fmt.Sprintf("%v", name.Value)
		}
	}
	return ""
}

func fetchSoftwareStatementJWKS(ssURL string, httpClient *http.Client) (goidc.JSONWebKeySet, error) {
	ssJWKSMu.Lock()
	defer ssJWKSMu.Unlock()

	if ssJWKSCache != nil && timeutil.Now().Before(ssJWKSLastFetchedAt.Add(ssJWKcacheTime)) {
		return *ssJWKSCache, nil
	}

	resp, err := httpClient.Get(ssURL)
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return goidc.JSONWebKeySet{}, fmt.Errorf("keystore jwks unexpected status code: %d", resp.StatusCode)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return goidc.JSONWebKeySet{}, fmt.Errorf("failed to decode keystore jwks response: %w", err)
	}

	ssJWKSCache = &jwks
	ssJWKSLastFetchedAt = timeutil.Now()
	return jwks, nil
}

func parseTimestamp(timestamp int) time.Time {
	return time.Unix(int64(timestamp), 0).UTC()
}

func marshalJSON(v any) datatypes.JSON {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic("failed to marshal json: " + err.Error())
	}
	return datatypes.JSON(bytes)
}

func unmarshalJSON(data datatypes.JSON, v any) error {
	if len(data) == 0 {
		return errors.New("data is empty")
	}

	return json.Unmarshal(data, v)
}
