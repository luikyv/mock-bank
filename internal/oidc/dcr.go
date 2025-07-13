package oidc

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

const (
	oidUID = "2.5.4.45"
)

var (
	ssJWKSCacheTime     = 1 * time.Hour
	ssJWKSMu            sync.Mutex
	ssJWKSCache         *goidc.JSONWebKeySet
	ssJWKSLastFetchedAt timeutil.DateTime
)

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

		if claims.IssuedAt == nil || timeutil.DateTimeNow().After(timeutil.NewDateTime(claims.IssuedAt.Time()).Add(5*time.Minute)) {
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

		if sID := c.CustomAttribute(SoftwareIDKey); sID != nil && sID != ss.SoftwareID {
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

		if webhookURIs, ok := c.CustomAttribute(WebhookURIsKey).([]string); ok {
			for _, webhookURI := range webhookURIs {
				if !slices.Contains(ss.SoftwareAPIWebhookURIs, webhookURI) {
					return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "webhook uri not allowed")
				}
			}
		}

		if c.PublicJWKS != nil {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "jwks cannot be informed by value")
		}

		if c.ScopeIDs == "" {
			c.ScopeIDs = strings.Join(scopeIDs, " ")
		}

		c.Name = ss.SoftwareClientName
		c.IDTokenKeyEncAlg = goidc.RSA_OAEP
		c.IDTokenContentEncAlg = goidc.A256GCM
		attrs := map[string]any{
			OrgIDKey:      ss.OrgID,
			SoftwareIDKey: ss.SoftwareID,
		}
		if ss.SoftwareOriginURIs != nil {
			attrs[OriginURIsKey] = ss.SoftwareOriginURIs
		}
		if uris, ok := c.CustomAttribute(WebhookURIsKey).([]any); ok {
			webhookURIs := make([]string, len(uris))
			for i, uri := range uris {
				webhookURIs[i] = uri.(string)
			}
			attrs[WebhookURIsKey] = webhookURIs
		}
		c.CustomAttributes = attrs
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
