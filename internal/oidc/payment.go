package oidc

import (
	"html/template"
	"net/http"

	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func PaymentPolicy(
	baseURL string,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
	paymentService payment.Service,
) goidc.AuthnPolicy {
	tmpl, err := template.ParseFS(templates, "login.html", "payment.html")
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
