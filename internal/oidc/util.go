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

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/enrollment"
	"github.com/luikyv/mock-bank/internal/payment"
)

const (
	HeaderClientCert = "X-Client-Cert"
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
	enrollmentService enrollment.Service,
) goidc.HandleGrantFunc {

	verifyEnrollment := func(ctx context.Context, id, orgID string) error {
		e, err := enrollmentService.Enrollment(ctx, enrollment.Query{ID: id}, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch enrollment for verifying grant: %w", err)
		}

		if !slices.Contains([]enrollment.Status{
			enrollment.StatusAwaitingEnrollment,
			enrollment.StatusAuthorized,
		}, e.Status) {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "enrollment is not in awaiting enrollment or authorized status")
		}

		return nil
	}

	verifyRecurringPaymentConsent := func(ctx context.Context, id, orgID string) error {
		c, err := autoPaymentService.Consent(ctx, id, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch payment consent for verifying grant: %w", err)
		}

		if !slices.Contains([]autopayment.ConsentStatus{
			autopayment.ConsentStatusAuthorized,
			autopayment.ConsentStatusPartiallyAccepted,
		}, c.Status) {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "payment consent is not authorized")
		}

		return nil
	}

	verifyPaymentConsent := func(ctx context.Context, id, orgID string) error {
		c, err := paymentService.Consent(ctx, id, orgID)
		if err != nil {
			return fmt.Errorf("could not fetch payment consent for verifying grant: %w", err)
		}

		if !slices.Contains([]payment.ConsentStatus{
			payment.ConsentStatusAuthorized,
			payment.ConsentStatusPartiallyAccepted,
		}, c.Status) {
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

		if enrollmentID, _ := enrollment.IDFromScopes(gi.ActiveScopes); enrollmentID != "" {
			return verifyEnrollment(r.Context(), enrollmentID, orgID)
		}

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
