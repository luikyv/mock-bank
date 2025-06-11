package oidc

import (
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/unrolled/secure"
)

//go:embed *.html
var templates embed.FS

func Policy(
	baseURL string,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
	paymentService payment.Service,
) goidc.AuthnPolicy {
	tmpl, err := template.ParseFS(templates, "login.html", "consent.html")
	if err != nil {
		panic(err)
	}
	authenticator := authenticator{
		tmpl:           tmpl,
		baseURL:        baseURL,
		userService:    userService,
		consentService: consentService,
		accountService: accountService,
		paymentService: paymentService,
	}
	return goidc.NewPolicy(
		"main",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			as.StoreParameter(paramStepID, stepIDSetUp)
			as.StoreParameter(paramOrgID, c.CustomAttribute(ClientAttrOrgID))
			return true
		},
		authenticator.authenticate,
	)
}

const (
	paramConsentID   = "consent_id"
	paramPermissions = "permissions"
	paramConsentCPF  = "consent_cpf"
	paramConsentCNPJ = "consent_cnpj"
	paramUserID      = "user_id"
	paramStepID      = "step_id"
	paramOrgID       = "org_id"

	stepIDSetUp      = "setup"
	stepIDLogin      = "login"
	stepIDConsent    = "consent"
	stepIDFinishFlow = "finish_flow"

	usernameFormParam = "username"
	passwordFormParam = "password"
	loginFormParam    = "login"
	consentFormParam  = "consent"
	accountsFormParam = "accounts"

	correctPassword = "pass"
)

type authnPage struct {
	CallbackID   string
	UserCPF      string
	BusinessCNPJ string
	Accounts     []account.Account
	Error        string
}

type authenticator struct {
	tmpl           *template.Template
	baseURL        string
	userService    user.Service
	consentService consent.Service
	accountService account.Service
	paymentService payment.Service
}

func (a authenticator) authenticate(w http.ResponseWriter, r *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	if session.StoredParameter(paramStepID) == stepIDSetUp {
		if status, err := a.setUp(r, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(paramStepID, stepIDLogin)
	}

	if session.StoredParameter(paramStepID) == stepIDLogin {
		if status, err := a.login(w, r, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(paramStepID, stepIDConsent)
	}

	if session.StoredParameter(paramStepID) == stepIDConsent {
		if status, err := a.grantConsent(w, r, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(paramStepID, stepIDFinishFlow)
	}

	if session.StoredParameter(paramStepID) == stepIDFinishFlow {
		return a.finishFlow(r, session)
	}

	return goidc.StatusFailure, errors.New("access denied")
}

func (a authenticator) setUp(r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	orgID := as.StoredParameter(paramOrgID).(string)

	consentID, ok := consent.IDFromScopes(as.Scopes)
	if !ok {
		return goidc.StatusFailure, errors.New("missing consent ID")
	}

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

	// if consent.BusinessCNPJ != "" && !user.OwnsCompany(consent.BusinessCNPJ) {
	// 	return goidc.StatusFailure, errors.New("the consent was created for a business that is not available to the logged user")
	// }

	// Convert permissions to []string for joining.
	permissionsStr := make([]string, len(consent.Permissions))
	for i, permission := range consent.Permissions {
		permissionsStr[i] = string(permission)
	}

	as.StoreParameter(paramConsentID, consentID)
	as.StoreParameter(paramPermissions, strings.Join(permissionsStr, " "))
	as.StoreParameter(paramConsentCPF, consent.UserCPF)
	if consent.BusinessCNPJ != "" {
		as.StoreParameter(paramConsentCNPJ, consent.BusinessCNPJ)
	}
	return goidc.StatusSuccess, nil
}

func (a authenticator) login(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	orgID := as.StoredParameter(paramOrgID).(string)
	consentID := as.StoredParameter(paramConsentID).(string)
	_ = r.ParseForm()

	isLogin := r.PostFormValue(loginFormParam)
	if isLogin == "" {
		slog.InfoContext(r.Context(), "rendering login page")
		return a.executeTemplate(w, r, "login.html", authnPage{
			CallbackID: as.CallbackID,
		})
	}

	if isLogin != "true" {
		_ = a.consentService.Reject(r.Context(), consentID, orgID, consent.RejectedByUser, consent.RejectionReasonCustomerManuallyRejected)
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	username := r.PostFormValue(usernameFormParam)
	user, err := a.userService.UserByUsername(r.Context(), username, orgID)
	if err != nil {
		return a.executeTemplate(w, r, "login.html", authnPage{
			CallbackID: as.CallbackID,
			Error:      "invalid username",
		})
	}

	password := r.PostFormValue(passwordFormParam)
	if user.CPF != as.StoredParameter(paramConsentCPF) || password != correctPassword {
		return a.executeTemplate(w, r, "login.html", authnPage{
			CallbackID: as.CallbackID,
			Error:      "invalid credentials",
		})
	}

	as.StoreParameter(paramUserID, user.ID.String())
	return goidc.StatusSuccess, nil
}

func (a authenticator) grantConsent(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {

	_ = r.ParseForm()

	isConsented := r.PostFormValue(consentFormParam)
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
	for _, accID := range r.Form[accountsFormParam] {
		accountIDs = append(accountIDs, uuid.MustParse(accID))
	}
	slog.InfoContext(r.Context(), "authorizing accounts", "accounts", accountIDs, "consent_id", c.ID)
	if err := a.accountService.Authorize(r.Context(), accountIDs, c.ID); err != nil {
		return goidc.StatusFailure, err
	}
	return goidc.StatusSuccess, nil
}

func (a authenticator) renderConsentPage(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	var permissions consent.Permissions
	for _, p := range strings.Split(as.StoredParameter(paramPermissions).(string), " ") {
		permissions = append(permissions, consent.Permission(p))
	}
	page := authnPage{
		CallbackID: as.CallbackID,
		UserCPF:    as.StoredParameter(paramConsentCPF).(string),
	}

	if permissions.HasAccountPermissions() {
		userID := as.StoredParameter(paramUserID).(string)
		orgID := as.StoredParameter(paramOrgID).(string)
		accs, err := a.accountService.AllAccounts(r.Context(), userID, orgID)
		slog.InfoContext(r.Context(), "rendering consent page with accounts", "accounts", accs)
		if err != nil {
			page.Error = "Could not load the user accounts"
			return a.executeTemplate(w, r, "consent.html", page)
		}
		page.Accounts = accs
	}

	if cnpj := as.StoredParameter(paramConsentCNPJ); cnpj != nil {
		page.BusinessCNPJ = cnpj.(string)
	}
	return a.executeTemplate(w, r, "consent.html", page)
}

func (a authenticator) finishFlow(r *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
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

func (a authenticator) executeTemplate(
	w http.ResponseWriter,
	r *http.Request,
	templateName string,
	params authnPage,
) (
	goidc.AuthnStatus,
	error,
) {
	nonce := secure.CSPNonce(r.Context())
	type page struct {
		BaseURL string
		Nonce   string
		authnPage
	}
	w.WriteHeader(http.StatusOK)
	_ = a.tmpl.ExecuteTemplate(w, templateName, page{
		BaseURL:   a.baseURL,
		Nonce:     nonce,
		authnPage: params,
	})
	return goidc.StatusInProgress, nil
}
