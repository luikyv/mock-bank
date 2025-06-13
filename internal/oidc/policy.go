package oidc

import (
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"slices"

	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/unrolled/secure"
)

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

//go:embed *.html
var templates embed.FS

type policy struct {
	tmpl        *template.Template
	baseURL     string
	userService user.Service
}

func (p policy) login(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	slog.InfoContext(r.Context(), "login step")

	orgID := as.StoredParameter(paramOrgID).(string)
	_ = r.ParseForm()

	isLogin := r.PostFormValue(formParamLogin)
	if isLogin == "" {
		slog.InfoContext(r.Context(), "rendering login page")
		return p.executeTemplate(w, r, "login", map[string]any{
			"CallbackID": as.CallbackID,
		})
	}

	if isLogin != "true" {
		return goidc.StatusFailure, errors.New("user cancelled login")
	}

	username := r.PostFormValue(formParamUsername)
	u, err := p.userService.UserByUsername(r.Context(), username, orgID)
	if err != nil {
		return p.executeTemplate(w, r, "login", map[string]any{
			"CallbackID": as.CallbackID,
			"Error":      "invalid username",
		})
	}

	password := r.PostFormValue(formParamPassword)
	if u.CPF != as.StoredParameter(paramCPF) || password != correctPassword {
		return p.executeTemplate(w, r, "login", map[string]any{
			"CallbackID": as.CallbackID,
			"Error":      "invalid credentials",
		})
	}

	as.StoreParameter(paramUserID, u.ID.String())
	return goidc.StatusSuccess, nil
}

func (a policy) finishFlow(_ http.ResponseWriter, r *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
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

func (p policy) executeTemplate(w http.ResponseWriter, r *http.Request, name string, params map[string]any) (goidc.AuthnStatus, error) {
	params["Nonce"] = secure.CSPNonce(r.Context())
	params["BaseURL"] = p.baseURL
	w.WriteHeader(http.StatusOK)
	_ = p.tmpl.ExecuteTemplate(w, name+".html", params)
	return goidc.StatusInProgress, nil
}
