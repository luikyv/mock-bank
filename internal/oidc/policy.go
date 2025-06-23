package oidc

import (
	"embed"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"github.com/unrolled/secure"
)

// TODO: Validate that the resources (accounts, ...) sent belong to the user.
// TODO: For auto payments: Mesmo se enviado pela ITP, o usuário pagador pode alterar durante a autorização do consentimento.

func Policies(
	baseURL string,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
	paymentService payment.Service,
	autoPaymentService autopayment.Service,
) []goidc.AuthnPolicy {
	tmpl := template.Must(template.ParseFS(templates, "login.html", "consent.html", "payment.html"))
	return []goidc.AuthnPolicy{
		goidc.NewPolicyWithSteps(
			"auto_payment",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				consentID, ok := autopayment.ConsentIDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(paramConsentID, consentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validateAutoPaymentConsentStep(autoPaymentService, userService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("payment", grantAutoPaymentStep(baseURL, tmpl, autoPaymentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthorizationStep()),
		),
		goidc.NewPolicyWithSteps(
			"payment",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				if !strings.Contains(as.Scopes, payment.Scope.ID) {
					return false
				}

				consentID, ok := consent.IDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(paramConsentID, consentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validatePaymentConsentStep(paymentService, userService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("payment", grantPaymentStep(baseURL, tmpl, paymentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthorizationStep()),
		),
		goidc.NewPolicyWithSteps(
			"consent",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				consentID, ok := consent.IDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(paramConsentID, consentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validateConsentStep(consentService, userService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("consent", grantConsentStep(baseURL, tmpl, consentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthorizationStep()),
		),
	}
}

//go:embed *.html
var templates embed.FS

const (
	paramConsentID = "consent_id"
	paramCPF       = "cpf"
	paramUserID    = "user_id"

	formParamUsername       = "username"
	formParamPassword       = "password"
	formParamLogin          = "login"
	formParamConsent        = "consent"
	formParamAccountIDs     = "accounts"
	formParamAccountID      = "account"
	formParamOverdraftLimit = "use_overdraft_limit"

	correctPassword = "pass"
)

func loginStep(baseURL string, tmpl *template.Template, userService user.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL    string
		CallbackID string
		Nonce      string
		Error      string
	}

	renderLoginPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		return renderPage(w, tmpl, "login", Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			Nonce:      secure.CSPNonce(r.Context()),
		})
	}

	renderLoginErrorPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, err string) (goidc.AuthnStatus, error) {
		return renderPage(w, tmpl, "login", Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			Nonce:      secure.CSPNonce(r.Context()),
			Error:      err,
		})
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "starting login step")

		isLogin := r.PostFormValue(formParamLogin)
		if isLogin == "" {
			slog.InfoContext(r.Context(), "rendering login page")
			return renderLoginPage(w, r, as)
		}

		if isLogin != "true" {
			slog.InfoContext(r.Context(), "user cancelled login")
			return goidc.StatusFailure, errors.New("user cancelled login")
		}

		orgID := as.StoredParameter(OrgIDKey).(string)
		username := r.PostFormValue(formParamUsername)
		u, err := userService.UserByUsername(r.Context(), username, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch user", "error", err)
			return renderLoginErrorPage(w, r, as, "invalid username")
		}

		password := r.PostFormValue(formParamPassword)
		if password != correctPassword {
			slog.InfoContext(r.Context(), "invalid password")
			return renderLoginErrorPage(w, r, as, "invalid credentials")
		}

		slog.InfoContext(r.Context(), "login step finished successfully", "user_id", u.ID, "user_cpf", u.CPF)
		as.StoreParameter(paramUserID, u.ID.String())
		as.StoreParameter(paramCPF, u.CPF)
		return goidc.StatusSuccess, nil
	}
}

func validateConsentStep(consentService consent.Service, userService user.Service) goidc.AuthnFunc {
	return func(_ http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		c, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch the consent", "error", err)
			return goidc.StatusFailure, err
		}

		if c.Status != consent.StatusAwaitingAuthorization {
			slog.InfoContext(r.Context(), "consent is not awaiting authorization", "status", c.Status)
			return goidc.StatusFailure, errors.New("consent is not awaiting authorization")
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

	renderConsentPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *consent.Consent) (goidc.AuthnStatus, error) {
		page := Page{
			BaseURL:    baseURL,
			UserCPF:    c.UserIdentification,
			CallbackID: as.CallbackID,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		userID := as.StoredParameter(paramUserID).(string)
		orgID := as.StoredParameter(OrgIDKey).(string)
		if c.Permissions.HasAccountPermissions() {
			slog.InfoContext(r.Context(), "rendering consent page with accounts")
			accs, err := accountService.AllAccounts(r.Context(), userID, orgID)
			if err != nil {
				slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
				return goidc.StatusFailure, fmt.Errorf("could not load the user accounts")
			}
			page.Accounts = accs
		}

		return renderPage(w, tmpl, "consent", page)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		c, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		if as.StoredParameter(paramCPF) != c.UserIdentification {
			slog.InfoContext(r.Context(), "consent was not created for the correct user")
			_ = consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByASPSP, consent.RejectionReasonInternalSecurityReason)
			return goidc.StatusFailure, errors.New("consent not created for the correct user")
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			slog.InfoContext(r.Context(), "rendering consent page")
			return renderConsentPage(w, r, as, c)
		}

		if isConsented != "true" {
			_ = consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByUser, consent.RejectionReasonCustomerManuallyRejected)
			return goidc.StatusFailure, errors.New("consent not granted")
		}

		slog.InfoContext(r.Context(), "authorizing consent")
		if err := consentService.Authorize(r.Context(), c); err != nil {
			return goidc.StatusFailure, err
		}

		if c.Permissions.HasAccountPermissions() {
			accountIDs := r.Form[formParamAccountIDs]
			slog.InfoContext(r.Context(), "authorizing accounts", "accounts", accountIDs)
			if err := accountService.Authorize(r.Context(), accountIDs, c.ID.String(), orgID); err != nil {
				slog.InfoContext(r.Context(), "could not authorize accounts", "error", err)
				return goidc.StatusFailure, err
			}
		}

		return goidc.StatusSuccess, nil
	}
}

func validatePaymentConsentStep(paymentService payment.Service, userService user.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch payment consent", "error", err)
			return goidc.StatusFailure, errors.New("could not fetch payment consent")
		}

		if c.Status != payment.ConsentStatusAwaitingAuthorization {
			slog.InfoContext(r.Context(), "payment consent is not awaiting authorization", "status", c.Status)
			return goidc.StatusFailure, errors.New("payment consent is not awaiting authorization")
		}

		return goidc.StatusSuccess, nil
	}
}

func grantPaymentStep(baseURL string, tmpl *template.Template, paymentService payment.Service, accountService account.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL        string
		CallbackID     string
		UserCPF        string
		BusinessCNPJ   string
		Account        *account.Account
		Accounts       []*account.Account
		OverdraftLimit bool
		Nonce          string
	}

	renderPaymentPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		userID := as.StoredParameter(paramUserID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		page := Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			UserCPF:    c.UserIdentification,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if cnpj := c.BusinessIdentification; cnpj != nil {
			page.BusinessCNPJ = *cnpj
		}

		if c.DebtorAccount != nil {
			page.Account = c.DebtorAccount
			return renderPage(w, tmpl, "payment", page)
		}

		accs, err := accountService.AllAccounts(r.Context(), userID, orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, errors.New("could not load the user accounts")
		}
		page.Accounts = accs

		return renderPage(w, tmpl, "payment", page)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		if as.StoredParameter(paramCPF) != c.UserIdentification {
			slog.InfoContext(r.Context(), "consent was not created for the correct user")
			_ = paymentService.RejectConsent(r.Context(), c, payment.ConsentRejectionNotProvided, "payment consent not created for the correct user")
			return goidc.StatusFailure, errors.New("consent not created for the correct user")
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			slog.InfoContext(r.Context(), "rendering payment consent page")
			return renderPaymentPage(w, r, as)
		}

		if isConsented != "true" {
			_ = paymentService.RejectConsent(r.Context(), c, payment.ConsentRejectionRejectedByUser, "payment consent not granted")
			return goidc.StatusFailure, errors.New("consent not granted")
		}

		slog.InfoContext(r.Context(), "authorizing payment consent", "consent_id", c.ID)
		if err := paymentService.AuthorizeConsent(r.Context(), c); err != nil {
			return goidc.StatusFailure, err
		}
		return goidc.StatusSuccess, nil
	}
}

func validateAutoPaymentConsentStep(paymentService autopayment.Service, userService user.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "setting up auto payment step")
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch recurring payment consent", "error", err)
			return goidc.StatusFailure, errors.New("could not fetch recurring payment consent")
		}

		if c.Status != autopayment.ConsentStatusAwaitingAuthorization {
			slog.InfoContext(r.Context(), "recurring payment consent is not awaiting authorization", "status", c.Status)
			return goidc.StatusFailure, errors.New("recurring payment consent is not awaiting authorization")
		}

		return goidc.StatusSuccess, nil
	}
}

func grantAutoPaymentStep(baseURL string, tmpl *template.Template, paymentService autopayment.Service, accountService account.Service) goidc.AuthnFunc {
	type Page struct {
		BaseURL                 string
		CallbackID              string
		UserCPF                 string
		BusinessCNPJ            string
		Account                 *account.Account
		Accounts                []*account.Account
		OverdraftLimitIsEnabled bool
		Nonce                   string
	}

	renderPaymentPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *autopayment.Consent) (goidc.AuthnStatus, error) {

		page := Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			UserCPF:    c.UserIdentification,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if c.Configuration.Automatic != nil {
			page.OverdraftLimitIsEnabled = true
		}

		if cnpj := c.BusinessIdentification; cnpj != nil {
			page.BusinessCNPJ = *cnpj
		}

		if c.DebtorAccount != nil {
			page.Account = c.DebtorAccount
			return renderPage(w, tmpl, "payment", page)
		}

		orgID := as.StoredParameter(OrgIDKey).(string)
		userID := as.StoredParameter(paramUserID).(string)
		accs, err := accountService.AllAccounts(r.Context(), userID, orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, errors.New("could not load the user accounts")
		}
		page.Accounts = accs

		return renderPage(w, tmpl, "payment", page)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(paramConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		if as.StoredParameter(paramCPF) != c.UserIdentification {
			slog.InfoContext(r.Context(), "consent was not created for the correct user")
			_ = paymentService.RejectConsent(r.Context(), c, autopayment.ConsentRejection{
				By:     autopayment.TerminatedByHolder,
				From:   autopayment.TerminatedFromHolder,
				Code:   autopayment.ConsentRejectionAuthenticationMismatch,
				Detail: "payment consent not created for the correct user",
			})
			return goidc.StatusFailure, errors.New("consent not created for the correct user")
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			slog.InfoContext(r.Context(), "rendering payment consent page")
			return renderPaymentPage(w, r, as, c)
		}

		if isConsented != "true" {
			_ = paymentService.RejectConsent(r.Context(), c, autopayment.ConsentRejection{
				From:   autopayment.TerminatedFromHolder,
				By:     autopayment.TerminatedByUser,
				Code:   autopayment.ConsentRejectionRejectedByUser,
				Detail: "payment consent not granted",
			})
			return goidc.StatusFailure, errors.New("consent not granted")
		}

		slog.InfoContext(r.Context(), "authorizing payment consent", "consent_id", consentID)

		accountID := uuid.MustParse(r.PostFormValue(formParamAccountID))
		c.DebtorAccountID = &accountID

		if c.Configuration.Automatic != nil && r.PostFormValue(formParamOverdraftLimit) == "true" {
			c.Configuration.Automatic.UseOverdraftLimit = true
		}

		if err := paymentService.AuthorizeConsent(r.Context(), c); err != nil {
			return goidc.StatusFailure, err
		}
		return goidc.StatusSuccess, nil
	}
}

func grantAuthorizationStep() goidc.AuthnFunc {
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

func renderPage(w http.ResponseWriter, tmpl *template.Template, name string, data any) (goidc.AuthnStatus, error) {
	if !strings.HasSuffix(name, ".html") {
		name = name + ".html"
	}

	w.WriteHeader(http.StatusOK)
	err := tmpl.ExecuteTemplate(w, name, data)
	if err != nil {
		return goidc.StatusFailure, fmt.Errorf("could not render template: %w", err)
	}
	return goidc.StatusInProgress, nil
}
