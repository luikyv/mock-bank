package oidc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const (
	HeaderClientCert = "X-Client-Cert"
)

func HandleGrantFunc(op *provider.Provider, consentService consent.Service) goidc.HandleGrantFunc {
	return func(r *http.Request, gi *goidc.GrantInfo) error {
		if gi.AdditionalTokenClaims == nil {
			gi.AdditionalTokenClaims = make(map[string]any)
		}
		client, err := op.Client(r.Context(), gi.ClientID)
		if err != nil {
			return fmt.Errorf("could not get client for verifying grant: %w", err)
		}
		gi.AdditionalTokenClaims["org_id"] = client.CustomAttribute("org_id")

		consentID, ok := consent.ID(gi.ActiveScopes)
		if !ok {
			return nil
		}

		consent, err := consentService.Consent(r.Context(), consentID)
		if err != nil {
			return fmt.Errorf("could not get consent for verifying grant: %w", err)
		}

		if !consent.IsAuthorized() {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "consent is not authorized")
		}

		return nil
	}
}

func ShoudIssueRefreshTokenFunc() goidc.ShouldIssueRefreshTokenFunc {
	return func(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
		return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) &&
			(grantInfo.GrantType == goidc.GrantAuthorizationCode || grantInfo.GrantType == goidc.GrantRefreshToken)
	}
}

func ClientCertFunc() goidc.ClientCertFunc {
	return func(r *http.Request) (*x509.Certificate, error) {
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
}

func LogErrorFunc() goidc.NotifyErrorFunc {
	return func(ctx context.Context, err error) {
		slog.InfoContext(ctx, "error during request", slog.String("error", err.Error()))
	}
}

func DCRFunc(scopes []goidc.Scope) goidc.HandleDynamicClientFunc {
	var scopeIDs []string
	for _, scope := range scopes {
		scopeIDs = append(scopeIDs, scope.ID)
	}
	scopeIDsStr := strings.Join(scopeIDs, " ")
	return func(r *http.Request, _ string, c *goidc.ClientMeta) error {
		c.ScopeIDs = scopeIDsStr
		return nil
	}
}

func TokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(goidc.PS256, 300)
	}
}
