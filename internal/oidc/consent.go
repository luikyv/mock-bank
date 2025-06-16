package oidc

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func ConsentPolicy(
	baseURL string,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
) goidc.AuthnPolicy {
	tmpl, err := template.ParseFS(templates, "login.html", "consent.html")
	if err != nil {
		panic(err)
	}
	policy := consentPolicy{
		consentService: consentService,
		accountService: accountService,
		policy: policy{
			tmpl:        tmpl,
			baseURL:     baseURL,
			userService: userService,
		},
	}
	return goidc.NewPolicyWithSteps(
		"consent",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			consentID, ok := consent.IDFromScopes(as.Scopes)
			if !ok {
				return false
			}

			as.StoreParameter(paramConsentID, consentID)
			as.StoreParameter(paramOrgID, c.CustomAttribute(ClientAttrOrgID))
			return true
		},
		goidc.NewAuthnStep("setup", policy.setUp),
		goidc.NewAuthnStep("login", policy.login),
		goidc.NewAuthnStep("consent", policy.grantConsent),
		goidc.NewAuthnStep("finish", policy.finishFlow),
	)
}

type consentPolicy struct {
	consentService consent.Service
	accountService account.Service
	policy
}

func (a consentPolicy) setUp(_ http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	orgID := as.StoredParameter(paramOrgID).(string)
	consentID := as.StoredParameter(paramConsentID).(string)

	consent, err := a.consentService.Consent(r.Context(), consentID, orgID)
	if err != nil {
		return goidc.StatusFailure, err
	}

	if !consent.IsAwaitingAuthorization() {
		return goidc.StatusFailure, errors.New("consent is not awaiting authorization")
	}

	_, err = a.userService.UserByCPF(r.Context(), consent.UserCPF, orgID)
	if err != nil {
		return goidc.StatusFailure, errors.New("the consent was created for an user that does not exist")
	}

	permissionsStr := make([]string, len(consent.Permissions))
	for i, permission := range consent.Permissions {
		permissionsStr[i] = string(permission)
	}

	as.StoreParameter(paramPermissions, strings.Join(permissionsStr, " "))
	as.StoreParameter(paramCPF, consent.UserCPF)
	if consent.BusinessCNPJ != nil {
		as.StoreParameter(paramCNPJ, *consent.BusinessCNPJ)
	}
	return goidc.StatusSuccess, nil
}

func (a consentPolicy) grantConsent(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {

	_ = r.ParseForm()

	isConsented := r.PostFormValue(formParamConsent)
	if isConsented == "" {
		slog.InfoContext(r.Context(), "rendering consent page")
		return a.renderConsentPage(w, r, as)
	}

	orgID := as.StoredParameter(paramOrgID).(string)
	consentID := as.StoredParameter(paramConsentID).(string)

	if isConsented != "true" {
		_ = a.consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByUser, consent.RejectionReasonCustomerManuallyRejected)
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	c, err := a.consentService.Consent(r.Context(), consentID, orgID)
	if err != nil {
		return goidc.StatusFailure, err
	}

	slog.InfoContext(r.Context(), "authorizing consent", "consent_id", c.ID)
	if err := a.consentService.Authorize(r.Context(), c); err != nil {
		return goidc.StatusFailure, err
	}

	var accountIDs []uuid.UUID
	for _, accID := range r.Form[formParamAccountIDs] {
		accountIDs = append(accountIDs, uuid.MustParse(accID))
	}
	slog.InfoContext(r.Context(), "authorizing accounts", "accounts", accountIDs, "consent_id", c.ID)
	if err := a.accountService.Authorize(r.Context(), accountIDs, c.ID); err != nil {
		return goidc.StatusFailure, err
	}
	return goidc.StatusSuccess, nil
}

func (a consentPolicy) renderConsentPage(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	var permissions consent.Permissions
	for _, p := range strings.Split(as.StoredParameter(paramPermissions).(string), " ") {
		permissions = append(permissions, consent.Permission(p))
	}
	page := map[string]any{
		"CallbackID": as.CallbackID,
		"UserCPF":    as.StoredParameter(paramCPF).(string),
	}

	if permissions.HasAccountPermissions() {
		userID := as.StoredParameter(paramUserID).(string)
		orgID := as.StoredParameter(paramOrgID).(string)
		accs, err := a.accountService.AllAccounts(r.Context(), userID, orgID)
		slog.InfoContext(r.Context(), "rendering consent page with accounts", "accounts", accs)
		if err != nil {
			slog.ErrorContext(r.Context(), "could not load the user accounts", "error", err)
			return goidc.StatusFailure, fmt.Errorf("could not load the user accounts")
		}
		page["Accounts"] = accs
	}

	if cnpj := as.StoredParameter(paramCNPJ); cnpj != nil {
		page["BusinessCNPJ"] = cnpj.(string)
	}
	return a.executeTemplate(w, r, "consent", page)
}
