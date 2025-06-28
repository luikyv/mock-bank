package oidc

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/enrollment"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/templates"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"github.com/unrolled/secure"
)

const (
	sessionParamConsentID    = "consent_id"
	sessionParamEnrollmentID = "enrollment_id"
	sessionParamCPF          = "cpf"
	sessionParamUserID       = "user_id"
	sessionParamBusinessID   = "business_id"

	formParamUsername       = "username"
	formParamPassword       = "password"
	formParamLogin          = "login"
	formParamConsent        = "consent"
	formParamAccountIDs     = "accounts"
	formParamAccountID      = "account"
	formParamOverdraftLimit = "use_overdraft_limit"

	correctPassword = "P@ssword01"
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
	enrollmentService enrollment.Service,
) []goidc.AuthnPolicy {
	tmpl := template.Must(template.ParseFS(templates.Templates, "*.html"))
	return []goidc.AuthnPolicy{
		goidc.NewPolicyWithSteps(
			"enrollment",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				enrollmentID, ok := enrollment.IDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(sessionParamEnrollmentID, enrollmentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validateEnrollmentStep(enrollmentService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("enrollment", grantEnrollmentStep(baseURL, tmpl, userService, enrollmentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthorizationStep()),
		),
		goidc.NewPolicyWithSteps(
			"auto_payment",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				consentID, ok := autopayment.ConsentIDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(sessionParamConsentID, consentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validateAutoPaymentConsentStep(autoPaymentService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("payment", grantAutoPaymentStep(baseURL, tmpl, userService, autoPaymentService, accountService)),
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

				as.StoreParameter(sessionParamConsentID, consentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validatePaymentConsentStep(paymentService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("payment", grantPaymentStep(baseURL, tmpl, userService, paymentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthorizationStep()),
		),
		goidc.NewPolicyWithSteps(
			"consent",
			func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
				consentID, ok := consent.IDFromScopes(as.Scopes)
				if !ok {
					return false
				}

				as.StoreParameter(sessionParamConsentID, consentID)
				as.StoreParameter(OrgIDKey, c.CustomAttribute(OrgIDKey))
				return true
			},
			goidc.NewAuthnStep("setup", validateConsentStep(consentService)),
			goidc.NewAuthnStep("login", loginStep(baseURL, tmpl, userService)),
			goidc.NewAuthnStep("consent", grantConsentStep(baseURL, tmpl, userService, consentService, accountService)),
			goidc.NewAuthnStep("finish", grantAuthorizationStep()),
		),
	}
}

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
		u, err := userService.User(r.Context(), user.Query{Username: username}, orgID)
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
		as.StoreParameter(sessionParamUserID, u.ID.String())
		as.StoreParameter(sessionParamCPF, u.CPF)
		return goidc.StatusSuccess, nil
	}
}

func validateConsentStep(consentService consent.Service) goidc.AuthnFunc {
	return func(_ http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(sessionParamConsentID).(string)
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

func grantConsentStep(
	baseURL string,
	tmpl *template.Template,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
) goidc.AuthnFunc {
	type Page struct {
		BaseURL      string
		CallbackID   string
		UserCPF      string
		BusinessCNPJ string
		Accounts     []*account.Account
		Nonce        string
	}

	renderConsentPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *consent.Consent) (goidc.AuthnStatus, error) {
		consentPage := Page{
			BaseURL:    baseURL,
			UserCPF:    c.UserIdentification,
			CallbackID: as.CallbackID,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		userID := as.StoredParameter(sessionParamUserID).(string)
		orgID := as.StoredParameter(OrgIDKey).(string)
		if c.Permissions.HasAccountPermissions() {
			slog.InfoContext(r.Context(), "rendering consent page with accounts")
			accs, err := accountService.Accounts(r.Context(), userID, orgID, page.NewPagination(nil, nil))
			if err != nil {
				slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
				return goidc.StatusFailure, fmt.Errorf("could not load the user accounts")
			}
			consentPage.Accounts = accs.Records
		}

		return renderPage(w, tmpl, "consent", consentPage)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(sessionParamConsentID).(string)
		c, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			if as.StoredParameter(sessionParamCPF) != c.UserIdentification {
				slog.InfoContext(r.Context(), "consent was not created for the correct user")
				_ = consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByASPSP, consent.RejectionReasonInternalSecurityReason)
				return goidc.StatusFailure, errors.New("consent not created for the correct user")
			}

			if c.BusinessIdentification != nil {
				userID := as.StoredParameter(sessionParamUserID).(string)
				business, err := userService.UserBusiness(r.Context(), userID, *c.BusinessIdentification, orgID)
				if err != nil {
					slog.InfoContext(r.Context(), "could not fetch the business", "error", err)
					_ = consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByASPSP, consent.RejectionReasonInternalSecurityReason)
					return goidc.StatusFailure, errors.New("user has no access to the business")
				}
				as.StoreParameter(sessionParamBusinessID, business.ID.String())
			}

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

func validatePaymentConsentStep(paymentService payment.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(sessionParamConsentID).(string)
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

func grantPaymentStep(
	baseURL string,
	tmpl *template.Template,
	userService user.Service,
	paymentService payment.Service,
	accountService account.Service,
) goidc.AuthnFunc {
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
		consentID := as.StoredParameter(sessionParamConsentID).(string)
		userID := as.StoredParameter(sessionParamUserID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		paymentPage := Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			UserCPF:    c.UserIdentification,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if cnpj := c.BusinessIdentification; cnpj != nil {
			paymentPage.BusinessCNPJ = *cnpj
		}

		if c.DebtorAccount != nil {
			paymentPage.Account = c.DebtorAccount
			return renderPage(w, tmpl, "payment", paymentPage)
		}

		accs, err := accountService.Accounts(r.Context(), userID, orgID, page.NewPagination(nil, nil))
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, errors.New("could not load the user accounts")
		}
		paymentPage.Accounts = accs.Records

		return renderPage(w, tmpl, "payment", paymentPage)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(sessionParamConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			if as.StoredParameter(sessionParamCPF) != c.UserIdentification {
				slog.InfoContext(r.Context(), "consent was not created for the correct user")
				_ = paymentService.RejectConsent(r.Context(), c, payment.ConsentRejectionNotProvided, "payment consent not created for the correct user")
				return goidc.StatusFailure, errors.New("consent not created for the correct user")
			}

			if c.BusinessIdentification != nil {
				userID := as.StoredParameter(sessionParamUserID).(string)
				business, err := userService.UserBusiness(r.Context(), userID, *c.BusinessIdentification, orgID)
				if err != nil {
					slog.InfoContext(r.Context(), "could not fetch the business", "error", err)
					_ = paymentService.RejectConsent(r.Context(), c, payment.ConsentRejectionNotProvided, "user has no access to the business")
					return goidc.StatusFailure, errors.New("user has no access to the business")
				}
				as.StoreParameter(sessionParamBusinessID, business.ID.String())
			}

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

func validateAutoPaymentConsentStep(paymentService autopayment.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "setting up auto payment step")
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(sessionParamConsentID).(string)
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

func grantAutoPaymentStep(
	baseURL string,
	tmpl *template.Template,
	userService user.Service,
	paymentService autopayment.Service,
	accountService account.Service,
) goidc.AuthnFunc {
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

		paymentPage := Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			UserCPF:    c.UserIdentification,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if c.Configuration.Automatic != nil {
			paymentPage.OverdraftLimitIsEnabled = true
		}

		if cnpj := c.BusinessIdentification; cnpj != nil {
			paymentPage.BusinessCNPJ = *cnpj
		}

		if c.DebtorAccount != nil {
			paymentPage.Account = c.DebtorAccount
			return renderPage(w, tmpl, "payment", paymentPage)
		}

		orgID := as.StoredParameter(OrgIDKey).(string)
		userID := as.StoredParameter(sessionParamUserID).(string)
		accs, err := accountService.Accounts(r.Context(), userID, orgID, page.NewPagination(nil, nil))
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, errors.New("could not load the user accounts")
		}
		paymentPage.Accounts = accs.Records

		return renderPage(w, tmpl, "payment", paymentPage)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		consentID := as.StoredParameter(sessionParamConsentID).(string)
		c, err := paymentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			if as.StoredParameter(sessionParamCPF) != c.UserIdentification {
				slog.InfoContext(r.Context(), "consent was not created for the correct user")
				_ = paymentService.RejectConsent(r.Context(), c, autopayment.ConsentRejection{
					By:     autopayment.TerminatedByHolder,
					From:   autopayment.TerminatedFromHolder,
					Code:   autopayment.ConsentRejectionAuthenticationMismatch,
					Detail: "payment consent not created for the correct user",
				})
				return goidc.StatusFailure, errors.New("consent not created for the correct user")
			}

			if c.BusinessIdentification != nil {
				userID := as.StoredParameter(sessionParamUserID).(string)
				business, err := userService.UserBusiness(r.Context(), userID, *c.BusinessIdentification, orgID)
				if err != nil {
					slog.InfoContext(r.Context(), "could not fetch the business", "error", err)
					_ = paymentService.RejectConsent(r.Context(), c, autopayment.ConsentRejection{
						By:     autopayment.TerminatedByHolder,
						From:   autopayment.TerminatedFromHolder,
						Code:   autopayment.ConsentRejectionAuthenticationMismatch,
						Detail: "user has no access to the business",
					})
					return goidc.StatusFailure, errors.New("user has no access to the business")
				}
				as.StoreParameter(sessionParamBusinessID, business.ID.String())
			}

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

func validateEnrollmentStep(enrollmentService enrollment.Service) goidc.AuthnFunc {
	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "setting up auto payment step")
		orgID := as.StoredParameter(OrgIDKey).(string)
		enrollmentID := as.StoredParameter(sessionParamEnrollmentID).(string)
		e, err := enrollmentService.Enrollment(r.Context(), enrollment.Query{ID: enrollmentID}, orgID)
		if err != nil {
			slog.InfoContext(r.Context(), "could not fetch enrollment", "error", err)
			return goidc.StatusFailure, errors.New("could not fetch enrollment")
		}

		if e.Status != enrollment.StatusAwaitingAccountHolderValidation {
			slog.InfoContext(r.Context(), "enrollment is not awaiting account holder validation", "status", e.Status)
			return goidc.StatusFailure, errors.New("enrollment is not awaiting account holder validation")
		}

		return goidc.StatusSuccess, nil
	}
}

func grantEnrollmentStep(
	baseURL string,
	tmpl *template.Template,
	userService user.Service,
	enrollmentService enrollment.Service,
	accountService account.Service,
) goidc.AuthnFunc {
	type Page struct {
		BaseURL      string
		CallbackID   string
		UserCPF      string
		BusinessCNPJ string
		Account      *account.Account
		Accounts     []*account.Account
		Nonce        string
	}

	renderEnrollmentPage := func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, e *enrollment.Enrollment) (goidc.AuthnStatus, error) {

		enrollmentPage := Page{
			BaseURL:    baseURL,
			CallbackID: as.CallbackID,
			UserCPF:    e.UserIdentification,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if e.BusinessIdentification != nil {
			enrollmentPage.BusinessCNPJ = *e.BusinessIdentification
		}

		if e.DebtorAccount != nil {
			enrollmentPage.Account = e.DebtorAccount
			return renderPage(w, tmpl, "enrollment", enrollmentPage)
		}

		orgID := as.StoredParameter(OrgIDKey).(string)
		userID := as.StoredParameter(sessionParamUserID).(string)
		accs, err := accountService.Accounts(r.Context(), userID, orgID, page.NewPagination(nil, nil))
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, errors.New("could not load the user accounts")
		}
		enrollmentPage.Accounts = accs.Records

		return renderPage(w, tmpl, "enrollment", enrollmentPage)
	}

	return func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		orgID := as.StoredParameter(OrgIDKey).(string)
		enrollmentID := as.StoredParameter(sessionParamEnrollmentID).(string)
		e, err := enrollmentService.Enrollment(r.Context(), enrollment.Query{ID: enrollmentID}, orgID)
		if err != nil {
			return goidc.StatusFailure, err
		}

		isConsented := r.PostFormValue(formParamConsent)
		if isConsented == "" {
			if as.StoredParameter(sessionParamCPF) != e.UserIdentification {
				slog.InfoContext(r.Context(), "enrollment was not created for the correct user")
				info := "enrollment not created for the correct user"
				reason := enrollment.RejectionReasonHybridFlowFailure
				_ = enrollmentService.Cancel(r.Context(), e, enrollment.Cancellation{
					From:            payment.CancelledFromHolder,
					RejectionReason: &reason,
					AdditionalInfo:  &info,
				})
				return goidc.StatusFailure, errors.New("enrollment not created for the correct user")
			}

			if e.BusinessIdentification != nil {
				userID := as.StoredParameter(sessionParamUserID).(string)
				business, err := userService.UserBusiness(r.Context(), userID, *e.BusinessIdentification, orgID)
				if err != nil {
					slog.InfoContext(r.Context(), "could not fetch the business", "error", err)
					info := "user has no access to the business"
					reason := enrollment.RejectionReasonHybridFlowFailure
					_ = enrollmentService.Cancel(r.Context(), e, enrollment.Cancellation{
						From:            payment.CancelledFromHolder,
						RejectionReason: &reason,
						AdditionalInfo:  &info,
					})
					return goidc.StatusFailure, errors.New("user has no access to the business")
				}
				as.StoreParameter(sessionParamBusinessID, business.ID.String())
			}

			slog.InfoContext(r.Context(), "rendering enrollment page")
			return renderEnrollmentPage(w, r, as, e)
		}

		if isConsented != "true" {
			info := "enrollment not granted"
			reason := enrollment.RejectionReasonManualRejection
			_ = enrollmentService.Cancel(r.Context(), e, enrollment.Cancellation{
				From:            payment.CancelledFromHolder,
				By:              &e.UserIdentification,
				RejectionReason: &reason,
				AdditionalInfo:  &info,
			})
			return goidc.StatusFailure, errors.New("enrollment not granted")
		}

		slog.InfoContext(r.Context(), "authorizing enrollment", "enrollment_id", enrollmentID)

		accountID := uuid.MustParse(r.PostFormValue(formParamAccountID))
		e.DebtorAccountID = &accountID

		if err := enrollmentService.AllowEnrollment(r.Context(), e); err != nil {
			return goidc.StatusFailure, err
		}
		return goidc.StatusSuccess, nil
	}
}

func grantAuthorizationStep() goidc.AuthnFunc {
	return func(_ http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
		slog.InfoContext(r.Context(), "auth flow finished, filling oauth session")

		sub := as.StoredParameter(sessionParamUserID).(string)
		if businessID := as.StoredParameter(sessionParamBusinessID); businessID != nil {
			sub = businessID.(string)
		}
		as.SetUserID(sub)
		as.GrantScopes(as.Scopes)
		as.SetIDTokenClaimACR(ACROpenBankingLOA2)
		as.SetIDTokenClaimAuthTime(timeutil.Timestamp())

		if as.Claims != nil {
			if slices.Contains(as.Claims.IDTokenEssentials(), goidc.ClaimACR) {
				as.SetIDTokenClaimACR(ACROpenBankingLOA2)
			}

			if slices.Contains(as.Claims.UserInfoEssentials(), goidc.ClaimACR) {
				as.SetUserInfoClaimACR(ACROpenBankingLOA2)
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
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		return goidc.StatusFailure, fmt.Errorf("could not render template: %w", err)
	}
	return goidc.StatusInProgress, nil
}
