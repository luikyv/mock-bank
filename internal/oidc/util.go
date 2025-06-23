package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

const (
	HeaderClientCert = "X-Client-Cert"
	oidUID           = "2.5.4.45"
)

var (
	ssJWKSCacheTime     = 1 * time.Hour
	ssJWKSMu            sync.Mutex
	ssJWKSCache         *goidc.JSONWebKeySet
	ssJWKSLastFetchedAt timeutil.DateTime
)

func TokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(goidc.PS256, 900)
	}
}

func HandleGrantFunc(
	op *provider.Provider,
	consentService consent.Service,
	paymentService payment.Service,
	autoPaymentService autopayment.Service,
) goidc.HandleGrantFunc {
	verifyRecurringPaymentConsent := func(ctx context.Context, id, orgID string) error {
		c, err := autoPaymentService.Consent(ctx, id, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch payment consent for verifying grant: %w", err)
		}

		if c.Status != autopayment.ConsentStatusAuthorized {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "payment consent is not authorized")
		}

		return nil
	}

	verifyPaymentConsent := func(ctx context.Context, id, orgID string) error {
		c, err := paymentService.Consent(ctx, id, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch payment consent for verifying grant: %w", err)
		}

		if c.Status != payment.ConsentStatusAuthorized {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "payment consent is not authorized")
		}

		return nil
	}

	verifyConsent := func(ctx context.Context, id, orgID string) error {
		c, err := consentService.Consent(ctx, id, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch consent for verifying grant: %w", err)
		}

		if c.Status != consent.StatusAuthorized {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "consent is not authorized")
		}

		return nil
	}

	return func(r *http.Request, gi *goidc.GrantInfo) error {
		if gi.AdditionalTokenClaims == nil {
			gi.AdditionalTokenClaims = make(map[string]any)
		}
		client, err := op.Client(r.Context(), gi.ClientID)
		if err != nil {
			return fmt.Errorf("could not get client for verifying grant: %w", err)
		}

		orgID := client.CustomAttribute(OrgIDKey).(string)
		gi.AdditionalTokenClaims[OrgIDKey] = orgID

		if recurringConsentID, _ := autopayment.ConsentIDFromScopes(gi.ActiveScopes); recurringConsentID != "" {
			return verifyRecurringPaymentConsent(r.Context(), recurringConsentID, orgID)
		}

		if consentID, _ := consent.IDFromScopes(gi.ActiveScopes); consentID != "" {
			if strings.Contains(gi.ActiveScopes, payment.Scope.ID) {
				return verifyPaymentConsent(r.Context(), consentID, orgID)
			}
			return verifyConsent(r.Context(), consentID, orgID)
		}

		return nil
	}
}

func HandlePARSessionFunc() goidc.HandleSessionFunc {
	return func(r *http.Request, as *goidc.AuthnSession, c *goidc.Client) error {
		as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
		return nil
	}
}

func ShouldIssueRefreshTokenFunc() goidc.ShouldIssueRefreshTokenFunc {
	return func(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
		return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) &&
			(grantInfo.GrantType == goidc.GrantAuthorizationCode || grantInfo.GrantType == goidc.GrantRefreshToken)
	}
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
	Scopes       []goidc.Scope
	KeyStoreHost string
	SSIssuer     string
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

		jwks, err := fetchSoftwareStatementJWKS(config.KeyStoreHost)
		if err != nil {
			return goidc.NewError(goidc.ErrorCodeInternalError, "could not fetch the keystore jwks")
		}

		parsedSSA, err := jwt.ParseSigned(ssa, []jose.SignatureAlgorithm{goidc.PS256})
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement", err)
		}

		var claims jwt.Claims
		var ss SoftwareStatement
		if err := parsedSSA.Claims(jwks.ToJOSE(), &claims, &ss); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid software statement signature", err)
		}

		if claims.IssuedAt == nil || timeutil.DateTimeNow().After(claims.IssuedAt.Time().Add(5*time.Minute)) {
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

		if sID := c.CustomAttribute("software_id"); sID != nil && sID != ss.SoftwareID {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "software id mismatch")
		}

		if orgID := c.CustomAttribute(OrgIDKey); orgID != nil && orgID != ss.OrgID {
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
			OrgIDKey:      ss.OrgID,
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

func fetchSoftwareStatementJWKS(keystoreHost string) (goidc.JSONWebKeySet, error) {
	ssJWKSMu.Lock()
	defer ssJWKSMu.Unlock()

	if ssJWKSCache != nil && timeutil.DateTimeNow().Before(ssJWKSLastFetchedAt.Add(ssJWKSCacheTime)) {
		return *ssJWKSCache, nil
	}

	resp, err := http.Get(keystoreHost + "/openbanking.jwks")
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
	ssJWKSLastFetchedAt = timeutil.DateTimeNow()
	return jwks, nil
}
