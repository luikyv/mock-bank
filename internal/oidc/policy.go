package oidc

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/autopayment"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/unrolled/secure"
)

// TODO: Validate that the resources (accounts, ...) sent belong to the user.

func Policies(
	baseURL string,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
	paymentService payment.Service,
	autoPaymentService autopayment.Service,
) []goidc.AuthnPolicy {
	loginTemplate := template.Must(template.ParseFS(templates, "login.html"))
	consentTemplate := template.Must(template.ParseFS(templates, "consent.html"))
	accountTemplate := template.Must(template.ParseFS(templates, "account.html"))
	paymentTemplate := template.Must(template.ParseFS(templates, "payment.html"))
	return []goidc.AuthnPolicy{
		goidc.NewPolicyWithSteps(
			"auto_payments",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				consentID, ok := autopayment.ConsentIDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(paramConsentID, consentID)
				as.StoreParameter(paramOrgID, c.CustomAttribute(ClientAttrOrgID))
				return true
			},
			goidc.NewAuthnStep("setup", setUpAutoPaymentStep(autoPaymentService, userService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, loginTemplate, userService)),
			goidc.NewAuthnStep("account", choosePaymentAccountStep(baseURL, accountTemplate, autoPaymentService, accountService)),
			goidc.NewAuthnStep("payment", grantAutoPaymentStep(baseURL, paymentTemplate, autoPaymentService)),
			goidc.NewAuthnStep("finish", grantAuthzStep()),
		),
		goidc.NewPolicyWithSteps(
			"payments",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				if !strings.Contains(as.Scopes, payment.Scope.ID) {
					return false
				}

				consentID, ok := consent.IDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(paramConsentID, consentID)
				as.StoreParameter(paramOrgID, c.CustomAttribute(ClientAttrOrgID))
				return true
			},
			goidc.NewAuthnStep("setup", setUpPaymentStep(paymentService, userService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, loginTemplate, userService)),
			goidc.NewAuthnStep("account", choosePaymentAccountStep(baseURL, accountTemplate, paymentService, accountService)),
			goidc.NewAuthnStep("payment", grantPaymentStep(baseURL, paymentTemplate, paymentService)),
			goidc.NewAuthnStep("finish", grantAuthzStep()),
		),
		goidc.NewPolicyWithSteps(
			"consents",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				consentID, ok := consent.IDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(paramConsentID, consentID)
				as.StoreParameter(paramOrgID, c.CustomAttribute(ClientAttrOrgID))
				return true
			},
			goidc.NewAuthnStep("setup", setUpConsentStep(consentService, userService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, loginTemplate, userService)),
			goidc.NewAuthnStep("consent", grantConsentStep(baseURL, consentTemplate, consentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthzStep()),
		),
	}
}

//go:embed *.html
var templates embed.FS

const (
	paramConsentID        = "consent_id"
	paramPermissions      = "permissions"
	paramCPF              = "cpf"
	paramCNPJ             = "cnpj"
	paramUserID           = "user_id"
	paramOrgID            = "org_id"
	paramPaymentConsentID = "payment_consent_id"
	paramAccountID        = "account_id"

	formParamUsername   = "username"
	formParamPassword   = "password"
	formParamLogin      = "login"
	formParamConsent    = "consent"
	formParamAccountIDs = "accounts"
	formParamAccountID  = "account"

	correctPassword = "pass"
)

func loginStep(baseURL string, tmpl *template.Template, userService user.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL    string
		CallbackID string
		Nonce      string
		Error      string
	}
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "login step")

		orgID := as.StoredParameter(paramOrgID).(string)
		_ = r.ParseForm()

		isLogin := r.PostFormValue(formParamLogin)
		if isLogin == "" {
			slog.InfoContext(r.Context(), "rendering login page")
			return executeTemplate(tmpl, w, Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				Nonce:      secure.CSPNonce(r.Context()),
			})
		}

		if isLogin != "true" {
			return goidc.StatusFailure, errors.New("user cancelled login")
		}

		username := r.PostFormValue(formParamUsername)
		u, err := userService.UserByUsername(r.Context(), username, orgID)
		if err != nil {
			return executeTemplate(tmpl, w, Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				Nonce:      secure.CSPNonce(r.Context()),
				Error:      "invalid username",
			})
		}

		if u.CPF != as.StoredParameter(paramCPF) {
			return executeTemplate(tmpl, w, Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				Nonce:      secure.CSPNonce(r.Context()),
				Error:      "the consent was not created for this user",
			})
		}

		password := r.PostFormValue(formParamPassword)
		if u.CPF != as.StoredParameter(paramCPF) || password != correctPassword {
			return executeTemplate(tmpl, w, Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				Nonce:      secure.CSPNonce(r.Context()),
				Error:      "invalid credentials",
			})
		}

		as.StoreParameter(paramUserID, u.ID.String())
		return goidc.StatusSuccess, nil
	}
}

func setUpConsentStep(consentService consent.Service, userService user.Service) goidc.AuthnFunc {
	return func(_ http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(paramOrgID).(string)
		consentID := as.StoredParameter(paramConsentID).(string)

		consent, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		if !consent.IsAwaitingAuthorization() {
			return goidc.StatusFailure, errors.New("consent is not awaiting authorization")
		}

		_, err = userService.UserByCPF(r.Context(), consent.UserCPF, orgID)
		if err != nil {
			return goidc.StatusFailure, errors.New("the consent was created for an user that does not exist")
		}

		as.StoreParameter(paramPermissions, consent.Permissions)
		as.StoreParameter(paramCPF, consent.UserCPF)
		if consent.BusinessCNPJ != nil {
			as.StoreParameter(paramCNPJ, *consent.BusinessCNPJ)
		}
		return goidc.StatusSuccess, nil
	}
}

func grantConsentStep(baseURL string, tmpl *template.Template, consentService consent.Service, accountService account.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL      string
		CallbackID   string
		UserCPF      string
		BusinessCNPJ string
		Accounts     []*account.Account
		Nonce        string
	}

	renderConsentPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		var permissions consent.Permissions
		for _, p := range as.StoredParameter(paramPermissions).([]string) {
			permissions = append(permissions, consent.Permission(p))
		}
		page := Page{
			BaseURL:    baseURL,
			UserCPF:    as.StoredParameter(paramCPF).(string),
			CallbackID: as.CallbackID,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if permissions.HasAccountPermissions() {
			userID := as.StoredParameter(paramUserID).(string)
			orgID := as.StoredParameter(paramOrgID).(string)
			accs, err := accountService.AllAccounts(r.Context(), userID, orgID)
			slog.InfoContext(r.Context(), "rendering consent page with accounts", "accounts", accs)
			if err != nil {
				slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
				return goidc.StatusFailure, fmt.Errorf("could not load the user accounts")
			}
			page.Accounts = accs
		}

		if cnpj := as.StoredParameter(paramCNPJ); cnpj != nil {
			page.BusinessCNPJ = cnpj.(string)
		}
		return executeTemplate(tmpl, w, page)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		_ = r.ParseForm()

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			slog.InfoContext(r.Context(), "rendering consent page")
			return renderConsentPage(w, r, as)
		}

		orgID := as.StoredParameter(paramOrgID).(string)
		consentID := as.StoredParameter(paramConsentID).(string)

		if isConsented != "true" {
			_ = consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByUser, consent.RejectionReasonCustomerManuallyRejected)
			return goidc.StatusFailure, errors.New("consent not granted")
		}

		c, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		slog.InfoContext(r.Context(), "authorizing consent", "consent_id", c.ID)
		if err := consentService.Authorize(r.Context(), c); err != nil {
			return goidc.StatusFailure, err
		}

		accountIDs := r.Form[formParamAccountIDs]
		slog.InfoContext(r.Context(), "authorizing accounts", "accounts", accountIDs, "consent_id", c.ID)
		if err := accountService.Authorize(r.Context(), accountIDs, c.ID.String(), orgID); err != nil {
			return goidc.StatusFailure, err
		}

		return goidc.StatusSuccess, nil
	}
}

func setUpPaymentStep(paymentService payment.Service, userService user.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(paramOrgID).(string)

		consentID, ok := consent.IDFromScopes(as.Scopes)
		if !ok {
			return goidc.StatusFailure, errors.New("missing payment consent ID")
		}

		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch payment consent", "error", err)
			return goidc.StatusFailure, errors.New("could not fetch payment consent")
		}

		if !c.IsAwaitingAuthorization() {
			slog.InfoContext(r.Context(), "payment consent is not awaiting authorization", "status", c.Status)
			return goidc.StatusFailure, errors.New("payment consent is not awaiting authorization")
		}

		_, err = userService.UserByCPF(r.Context(), c.UserCPF, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch user", "error", err)
			return goidc.StatusFailure, errors.New("the consent was created for an user that does not exist")
		}

		as.StoreParameter(paramPaymentConsentID, consentID)
		as.StoreParameter(paramCPF, c.UserCPF)
		if c.BusinessCNPJ != nil {
			as.StoreParameter(paramCNPJ, *c.BusinessCNPJ)
		}
		if c.DebtorAccountID != nil {
			as.StoreParameter(paramAccountID, *c.DebtorAccountID)
		}
		return goidc.StatusSuccess, nil
	}
}

func setUpAutoPaymentStep(paymentService autopayment.Service, userService user.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(paramOrgID).(string)

		consentID, ok := autopayment.ConsentIDFromScopes(as.Scopes)
		if !ok {
			return goidc.StatusFailure, errors.New("missing recurring payment consent ID")
		}

		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch recurring payment consent", "error", err)
			return goidc.StatusFailure, errors.New("could not fetch recurring payment consent")
		}

		if !c.IsAwaitingAuthorization() {
			slog.InfoContext(r.Context(), "recurring payment consent is not awaiting authorization", "status", c.Status)
			return goidc.StatusFailure, errors.New("recurring payment consent is not awaiting authorization")
		}

		_, err = userService.UserByCPF(r.Context(), c.UserCPF, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch user", "error", err)
			return goidc.StatusFailure, errors.New("the consent was created for an user that does not exist")
		}

		as.StoreParameter(paramPaymentConsentID, consentID)
		as.StoreParameter(paramCPF, c.UserCPF)
		if c.BusinessCNPJ != nil {
			as.StoreParameter(paramCNPJ, *c.BusinessCNPJ)
		}
		if c.DebtorAccountID != nil {
			as.StoreParameter(paramAccountID, *c.DebtorAccountID)
		}
		return goidc.StatusSuccess, nil
	}
}

func choosePaymentAccountStep(
	baseURL string,
	tmpl *template.Template,
	paymentService interface {
		UpdateDebtorAccount(ctx context.Context, consentID, accountID, orgID string) error
	},
	accountService account.Service,
) goidc.AuthnFunc {
	type Page struct {
		BaseURL      string
		CallbackID   string
		Accounts     []*account.Account
		BusinessCNPJ string
		Nonce        string
	}
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {

		// Skip if the account id is already defined.
		if as.StoredParameter(paramAccountID) != nil {
			return goidc.StatusSuccess, nil
		}

		orgID := as.StoredParameter(paramOrgID).(string)
		consentID := as.StoredParameter(paramPaymentConsentID).(string)

		_ = r.ParseForm()
		accountID := r.PostFormValue(formParamAccountID)
		if accountID == "" {
			userID := as.StoredParameter(paramUserID).(string)
			accs, err := accountService.AllAccounts(r.Context(), userID, orgID)
			if err != nil {
				slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
				return goidc.StatusFailure, errors.New("could not load the user accounts")
			}

			slog.InfoContext(r.Context(), "rendering account page", "accounts", accs)
			page := Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				Nonce:      secure.CSPNonce(r.Context()),
				Accounts:   accs,
			}
			if cnpj := as.StoredParameter(paramCNPJ); cnpj != nil {
				page.BusinessCNPJ = cnpj.(string)
			}
			return executeTemplate(tmpl, w, page)
		}

		if err := paymentService.UpdateDebtorAccount(r.Context(), consentID, accountID, orgID); err != nil {
			slog.ErrorContext(r.Context(), "could not update debtor account", "error", err)
			return goidc.StatusFailure, errors.New("could not update debtor account")
		}
		return goidc.StatusSuccess, nil
	}
}

func grantPaymentStep(baseURL string, tmpl *template.Template, paymentService payment.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL      string
		CallbackID   string
		UserCPF      string
		BusinessCNPJ string
		Consent      *payment.Consent
		Nonce        string
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(paramOrgID).(string)
		consentID := as.StoredParameter(paramPaymentConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		_ = r.ParseForm()

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			slog.InfoContext(r.Context(), "rendering payment consent page")
			page := Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				UserCPF:    as.StoredParameter(paramCPF).(string),
				Consent:    c,
				Nonce:      secure.CSPNonce(r.Context()),
			}

			if cnpj := as.StoredParameter(paramCNPJ); cnpj != nil {
				page.BusinessCNPJ = cnpj.(string)
			}

			return executeTemplate(tmpl, w, page)
		}

		if isConsented != "true" {
			_ = paymentService.RejectConsent(r.Context(), consentID, orgID, payment.ConsentRejectionRejectedByUser, "payment consent not granted")
			return goidc.StatusFailure, errors.New("consent not granted")
		}

		slog.InfoContext(r.Context(), "authorizing payment consent", "consent_id", c.ID)
		if err := paymentService.AuthorizeConsent(r.Context(), c); err != nil {
			return goidc.StatusFailure, err
		}
		return goidc.StatusSuccess, nil
	}
}

func grantAutoPaymentStep(baseURL string, tmpl *template.Template, paymentService autopayment.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL      string
		CallbackID   string
		UserCPF      string
		BusinessCNPJ string
		Consent      *autopayment.Consent
		Nonce        string
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(paramOrgID).(string)
		consentID := as.StoredParameter(paramPaymentConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		_ = r.ParseForm()

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			slog.InfoContext(r.Context(), "rendering payment consent page")
			page := Page{
				BaseURL:    baseURL,
				CallbackID: as.CallbackID,
				UserCPF:    as.StoredParameter(paramCPF).(string),
				Consent:    c,
				Nonce:      secure.CSPNonce(r.Context()),
			}

			if cnpj := as.StoredParameter(paramCNPJ); cnpj != nil {
				page.BusinessCNPJ = cnpj.(string)
			}

			return executeTemplate(tmpl, w, page)
		}

		if isConsented != "true" {
			_ = paymentService.RejectConsent(r.Context(), consentID, orgID, autopayment.ConsentRejection{
				From:   autopayment.TerminatedFromHolder,
				By:     autopayment.TerminatedByUser,
				Code:   autopayment.ConsentRejectionRejectedByUser,
				Detail: "payment consent not granted",
			})
			return goidc.StatusFailure, errors.New("consent not granted")
		}

		slog.InfoContext(r.Context(), "authorizing payment consent", "consent_id", c.ID)
		if err := paymentService.AuthorizeConsent(r.Context(), c); err != nil {
			return goidc.StatusFailure, err
		}
		return goidc.StatusSuccess, nil
	}
}

func grantAuthzStep() goidc.AuthnFunc {
	return func(_ http.ResponseWriter, r *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "auth flow finished, filling oauth session")

		session.SetUserID(session.StoredParameter(paramUserID).(string))
		session.GrantScopes(session.Scopes)
		session.SetIDTokenClaimACR(ACROpenBankingLOA2)
		session.SetIDTokenClaimAuthTime(timeutil.Timestamp())

		if session.Claims != nil {
			if slices.Contains(session.Claims.IDTokenEssentials(), goidc.ClaimACR) {
				session.SetIDTokenClaimACR(ACROpenBankingLOA2)
			}

			if slices.Contains(session.Claims.UserInfoEssentials(), goidc.ClaimACR) {
				session.SetUserInfoClaimACR(ACROpenBankingLOA2)
			}
		}

		return goidc.StatusSuccess, nil
	}
}

func executeTemplate(tmpl *template.Template, w http.ResponseWriter, data any) (goidc.AuthnStatus, error) {
	w.WriteHeader(http.StatusOK)
	err := tmpl.Execute(w, data)
	if err != nil {
		return goidc.StatusFailure, fmt.Errorf("could not render template: %w", err)
	}
	return goidc.StatusInProgress, nil
}
