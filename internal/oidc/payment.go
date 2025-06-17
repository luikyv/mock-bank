package oidc

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func PaymentPolicy(
	baseURL string,
	userService user.Service,
	paymentService payment.Service,
	accountService account.Service,
) goidc.AuthnPolicy {
	tmpl, err := template.ParseFS(templates, "login.html", "account.html", "payment.html")
	if err != nil {
		panic(err)
	}
	policy := paymentPolicy{
		accountService: accountService,
		paymentService: paymentService,
		policy: policy{
			tmpl:        tmpl,
			baseURL:     baseURL,
			userService: userService,
		},
	}

	return goidc.NewPolicyWithSteps(
		"payment",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			if !strings.Contains(as.Scopes, payment.Scope.ID) {
				return false
			}

			as.StoreParameter(paramOrgID, c.CustomAttribute(ClientAttrOrgID))
			return true
		},
		goidc.NewAuthnStep("setup", policy.setUp),
		goidc.NewAuthnStep("login", policy.login),
		goidc.NewAuthnStep("account", policy.chooseAccount),
		goidc.NewAuthnStep("payment", policy.grantPayment),
		goidc.NewAuthnStep("finish", policy.finishFlow),
	)
}

type paymentPolicy struct {
	accountService account.Service
	paymentService payment.Service
	policy
}

func (policy paymentPolicy) setUp(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	orgID := as.StoredParameter(paramOrgID).(string)

	consentID, ok := consent.IDFromScopes(as.Scopes)
	if !ok {
		return goidc.StatusFailure, errors.New("missing payment consent ID")
	}

	c, err := policy.paymentService.Consent(r.Context(), consentID, orgID)
	if err != nil {
		slog.InfoContext(r.Context(), "could not fetch payment consent", "error", err)
		return goidc.StatusFailure, errors.New("could not fetch payment consent")
	}

	if !c.IsAwaitingAuthorization() {
		slog.InfoContext(r.Context(), "payment consent is not awaiting authorization", "status", c.Status)
		return goidc.StatusFailure, errors.New("payment consent is not awaiting authorization")
	}

	_, err = policy.userService.UserByCPF(r.Context(), c.UserCPF, orgID)
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

func (p paymentPolicy) chooseAccount(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {

	if as.StoredParameter(paramAccountID) != nil {
		return goidc.StatusSuccess, nil
	}

	orgID := as.StoredParameter(paramOrgID).(string)
	consentID := as.StoredParameter(paramPaymentConsentID).(string)

	_ = r.ParseForm()
	accountID := r.PostFormValue(formParamAccountID)
	if accountID == "" {
		userID := as.StoredParameter(paramUserID).(string)
		accs, err := p.accountService.AllAccounts(r.Context(), userID, orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, errors.New("could not load the user accounts")
		}

		slog.InfoContext(r.Context(), "rendering account page", "accounts", accs)
		// TODO: Make this a struct.
		return p.executeTemplate(w, r, "account", map[string]any{
			"CallbackID": as.CallbackID,
			"Accounts":   accs,
		})
	}

	if err := p.paymentService.UpdateDebtorAccount(r.Context(), consentID, accountID, orgID); err != nil {
		slog.ErrorContext(r.Context(), "could not update debtor account", "error", err)
		return goidc.StatusFailure, errors.New("could not update debtor account")
	}
	return goidc.StatusSuccess, nil
}

func (p paymentPolicy) grantPayment(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	orgID := as.StoredParameter(paramOrgID).(string)
	consentID := as.StoredParameter(paramPaymentConsentID).(string)
	c, err := p.paymentService.Consent(r.Context(), consentID, orgID)
	if err != nil {
		return goidc.StatusFailure, err
	}

	_ = r.ParseForm()

	isConsented := r.PostFormValue(formParamConsent)
	if isConsented == "" {
		slog.InfoContext(r.Context(), "rendering payment consent page")
		page := map[string]any{
			"CallbackID":            as.CallbackID,
			"UserCPF":               as.StoredParameter(paramCPF).(string),
			"DebtorAccount":         c.DebtorAccount,
			"CreditorName":          c.CreditorName,
			"CreditorCPFCNPJ":       c.CreditorCPFCNPJ,
			"CreditorAccountISBP":   c.CreditorAccountISBP,
			"CreditorAccountIssuer": c.CreditorAccountIssuer,
			"CreditorAccountNumber": c.CreditorAccountNumber,
			"PaymentAmount":         c.PaymentAmount,
			"PaymentCurrency":       c.PaymentCurrency,
			"PaymentDate":           c.PaymentDate,
		}

		if cnpj := as.StoredParameter(paramCNPJ); cnpj != nil {
			page["BusinessCNPJ"] = cnpj.(string)
		}

		return p.executeTemplate(w, r, "payment", page)
	}

	if isConsented != "true" {
		_ = p.paymentService.RejectConsent(r.Context(), consentID, orgID, payment.ConsentRejectionRejectedByUser, "payment consent not granted")
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	slog.InfoContext(r.Context(), "authorizing payment consent", "consent_id", c.ID)
	if err := p.paymentService.AuthorizeConsent(r.Context(), c); err != nil {
		return goidc.StatusFailure, err
	}
	return goidc.StatusSuccess, nil
}
