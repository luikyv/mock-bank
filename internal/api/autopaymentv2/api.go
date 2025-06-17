//go:generate oapi-codegen -config=./config.yml -package=autopaymentv2 -o=./api_gen.go ./swagger.yml
package autopaymentv2

import (
	"context"
	"crypto"
	"net/http"

	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/autopayment"
	"github.com/luiky/mock-bank/internal/idempotency"
	"github.com/luiky/mock-bank/internal/jwtutil"
	"github.com/luiky/mock-bank/internal/oidc"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

var _ StrictServerInterface = Server{}

type Server struct {
	baseURL            string
	service            autopayment.Service
	idempotencyService idempotency.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	host string,
	service autopayment.Service,
	idempotencyService idempotency.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		baseURL:            host + "/open-banking/automatic-payments/v2",
		service:            service,
		idempotencyService: idempotencyService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	autoPaymentMux := http.NewServeMux()

	jwtMiddleware := jwtutil.Middleware(s.baseURL, s.orgID, s.keystoreHost, s.signer)
	idempotencyMiddleware := idempotency.Middleware(s.idempotencyService)
	clientCredentialsAuthMiddleware := oidc.AuthMiddleware(s.op, autopayment.Scope)
	authCodeAuthMiddleware := oidc.AuthMiddleware(s.op, goidc.ScopeOpenID, autopayment.ScopeConsentID)
	swaggerMiddleware, swaggerVersion := api.SwaggerMiddleware(GetSwagger, "PARAMETRO_INVALIDO")
	xvMiddleware := api.XVMiddleware(swaggerVersion)

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{
			xvMiddleware,
			swaggerMiddleware,
			api.FAPIIDMiddleware(nil),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsPostRecurringConsents)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("POST /recurring-consents", handler)

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsGetRecurringConsentsConsentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("GET /recurring-consents/{recurringConsentId}", handler)

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsPatchRecurringConsentsConsentID)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("PATCH /recurring-consents/{recurringConsentId}", handler)

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsPostPixRecurringPayments)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	autoPaymentMux.Handle("POST /pix/recurring-payments", handler)

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsGetPixRecurringPaymentsPaymentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("GET /pix/recurring-payments/{recurringPaymentId}", handler)

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsGetPixRecurringPayments)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("GET /pix/recurring-payments", handler)

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsPatchRecurringConsentsConsentID)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("PATCH /pix/payments/recurring-consents/{recurringConsentId}", handler)

	mux.Handle("/open-banking/automatic-payments/v2/", http.StripPrefix("/open-banking/automatic-payments/v2", autoPaymentMux))
}

func (s Server) AutomaticPaymentsPostRecurringConsents(ctx context.Context, req AutomaticPaymentsPostRecurringConsentsRequestObject) (AutomaticPaymentsPostRecurringConsentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c := &autopayment.Consent{
		UserCPF:        req.Body.Data.LoggedUser.Document.Identification,
		ExpiresAt:      req.Body.Data.ExpirationDateTime,
		AdditionalInfo: req.Body.Data.AdditionalInformation,
		Configuration:  req.Body.Data.RecurringConfiguration,
		ClientID:       clientID,
		OrgID:          orgID,
	}
	if req.Body.Data.BusinessEntity != nil {
		c.BusinessCNPJ = &req.Body.Data.BusinessEntity.Document.Identification
	}

	for _, creditor := range req.Body.Data.Creditors {
		c.Creditors = append(c.Creditors, autopayment.Creditor{
			Type:    payment.CreditorType(creditor.PersonType),
			CPFCNPJ: creditor.CpfCnpj,
			Name:    creditor.Name,
		})
	}

	var debtorAccount *payment.Account
	if req.Body.Data.DebtorAccount != nil {
		debtorAccount = &payment.Account{
			ISPB:   req.Body.Data.DebtorAccount.Ispb,
			Issuer: req.Body.Data.DebtorAccount.Issuer,
			Number: req.Body.Data.DebtorAccount.Number,
			Type:   payment.AccountType(req.Body.Data.DebtorAccount.AccountType),
		}
	}
	if err := s.service.CreateConsent(ctx, c, debtorAccount); err != nil {
		return nil, err
	}

	resp := ResponsePostRecurringConsent{
		Data: struct {
			AdditionalInformation *string            "json:\"additionalInformation,omitempty\""
			AuthorisedAtDateTime  *timeutil.DateTime "json:\"authorisedAtDateTime,omitempty\""
			BusinessEntity        *BusinessEntity    "json:\"businessEntity,omitempty\""
			CreationDateTime      timeutil.DateTime  "json:\"creationDateTime\""
			Creditors             Creditors          "json:\"creditors\""
			DebtorAccount         *struct {
				AccountType EnumAccountTypeConsents "json:\"accountType\""
				Ispb        string                  "json:\"ispb\""
				Issuer      *string                 "json:\"issuer,omitempty\""
				Number      string                  "json:\"number\""
			} "json:\"debtorAccount,omitempty\""
			ExpirationDateTime     *timeutil.DateTime     "json:\"expirationDateTime,omitempty\""
			LoggedUser             LoggedUser             "json:\"loggedUser\""
			RecurringConfiguration RecurringConfiguration "json:\"recurringConfiguration\""
			RecurringConsentID     string                 "json:\"recurringConsentId\""
			Rejection              *Rejection             "json:\"rejection,omitempty\""
			Revocation             *struct {
				Reason *struct {
					Code   ResponsePostRecurringConsentDataRevocationReasonCode "json:\"code\""
					Detail string                                               "json:\"detail\""
				} "json:\"reason,omitempty\""
				RevokedAt   timeutil.DateTime                                     "json:\"revokedAt\""
				RevokedBy   ResponsePostRecurringConsentDataRevocationRevokedBy   "json:\"revokedBy\""
				RevokedFrom ResponsePostRecurringConsentDataRevocationRevokedFrom "json:\"revokedFrom\""
			} "json:\"revocation,omitempty\""
			Status               EnumAuthorisationStatusType "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime           "json:\"statusUpdateDateTime\""
			UpdatedAtDateTime    *timeutil.DateTime          "json:\"updatedAtDateTime,omitempty\""
		}{
			AdditionalInformation: c.AdditionalInfo,
			CreationDateTime:      c.CreatedAt,
			ExpirationDateTime:    c.ExpiresAt,
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserCPF,
					Rel:            "CPF",
				},
			},
			RecurringConfiguration: c.Configuration,
			RecurringConsentID:     c.URN(),
			Status:                 EnumAuthorisationStatusType(c.Status),
			UpdatedAtDateTime:      &c.UpdatedAt,
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/recurring-consents/" + c.URN()),
	}

	for _, creditor := range c.Creditors {
		resp.Data.Creditors = append(resp.Data.Creditors, struct {
			CpfCnpj    string                "json:\"cpfCnpj\""
			Name       string                "json:\"name\""
			PersonType EnumPaymentPersonType "json:\"personType\""
		}{
			CpfCnpj:    creditor.CPFCNPJ,
			Name:       creditor.Name,
			PersonType: EnumPaymentPersonType(creditor.Type),
		})
	}

	if c.BusinessCNPJ != nil {
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: *c.BusinessCNPJ,
				Rel:            "CNPJ",
			},
		}
	}

	if c.DebtorAccount != nil {
		branch := account.DefaultBranch
		resp.Data.DebtorAccount = &struct {
			AccountType EnumAccountTypeConsents "json:\"accountType\""
			Ispb        string                  "json:\"ispb\""
			Issuer      *string                 "json:\"issuer,omitempty\""
			Number      string                  "json:\"number\""
		}{
			Ispb:        api.MockBankISPB,
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountTypeConsents(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
	}

	return AutomaticPaymentsPostRecurringConsents201JSONResponse{RecurringConsentsPostJSONResponse(resp)}, nil
}

func (s Server) AutomaticPaymentsGetRecurringConsentsConsentID(ctx context.Context, req AutomaticPaymentsGetRecurringConsentsConsentIDRequestObject) (AutomaticPaymentsGetRecurringConsentsConsentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c, err := s.service.Consent(ctx, req.RecurringConsentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponseRecurringConsent{
		Data: struct {
			AdditionalInformation *string              "json:\"additionalInformation,omitempty\""
			ApprovalDueDate       *timeutil.BrazilDate "json:\"approvalDueDate,omitempty\""
			AuthorisedAtDateTime  *timeutil.DateTime   "json:\"authorisedAtDateTime,omitempty\""
			BusinessEntity        *BusinessEntity      "json:\"businessEntity,omitempty\""
			CreationDateTime      timeutil.DateTime    "json:\"creationDateTime\""
			Creditors             Creditors            "json:\"creditors\""
			DebtorAccount         *struct {
				AccountType  EnumAccountTypeConsents "json:\"accountType\""
				IbgeTownCode *string                 "json:\"ibgeTownCode,omitempty\""
				Ispb         string                  "json:\"ispb\""
				Issuer       *string                 "json:\"issuer,omitempty\""
				Number       string                  "json:\"number\""
			} "json:\"debtorAccount,omitempty\""
			ExpirationDateTime     *timeutil.DateTime     "json:\"expirationDateTime,omitempty\""
			LoggedUser             LoggedUser             "json:\"loggedUser\""
			RecurringConfiguration RecurringConfiguration "json:\"recurringConfiguration\""
			RecurringConsentID     string                 "json:\"recurringConsentId\""
			Rejection              *Rejection             "json:\"rejection,omitempty\""
			Revocation             *struct {
				Reason *struct {
					Code   ResponseRecurringConsentDataRevocationReasonCode "json:\"code\""
					Detail string                                           "json:\"detail\""
				} "json:\"reason,omitempty\""
				RevokedAt   timeutil.DateTime                                 "json:\"revokedAt\""
				RevokedBy   ResponseRecurringConsentDataRevocationRevokedBy   "json:\"revokedBy\""
				RevokedFrom ResponseRecurringConsentDataRevocationRevokedFrom "json:\"revokedFrom\""
			} "json:\"revocation,omitempty\""
			RiskSignals          *RiskSignalsConsents        "json:\"riskSignals,omitempty\""
			Status               EnumAuthorisationStatusType "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime           "json:\"statusUpdateDateTime\""
			UpdatedAtDateTime    *timeutil.DateTime          "json:\"updatedAtDateTime,omitempty\""
		}{
			RecurringConsentID:     c.URN(),
			AdditionalInformation:  c.AdditionalInfo,
			ApprovalDueDate:        c.ApprovalDueAt,
			AuthorisedAtDateTime:   c.AuthorizedAt,
			CreationDateTime:       c.CreatedAt,
			ExpirationDateTime:     c.ExpiresAt,
			Status:                 EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime:   c.StatusUpdatedAt,
			UpdatedAtDateTime:      &c.UpdatedAt,
			RecurringConfiguration: c.Configuration,
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserCPF,
					Rel:            "CPF",
				},
			},
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/recurring-consents/" + c.URN()),
	}

	for _, creditor := range c.Creditors {
		resp.Data.Creditors = append(resp.Data.Creditors, struct {
			CpfCnpj    string                "json:\"cpfCnpj\""
			Name       string                "json:\"name\""
			PersonType EnumPaymentPersonType "json:\"personType\""
		}{
			CpfCnpj:    creditor.CPFCNPJ,
			Name:       creditor.Name,
			PersonType: EnumPaymentPersonType(creditor.Type),
		})
	}

	if c.BusinessCNPJ != nil {
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: *c.BusinessCNPJ,
				Rel:            "CNPJ",
			},
		}
	}

	if c.DebtorAccount != nil {
		branch := account.DefaultBranch
		resp.Data.DebtorAccount = &struct {
			AccountType  EnumAccountTypeConsents "json:\"accountType\""
			IbgeTownCode *string                 "json:\"ibgeTownCode,omitempty\""
			Ispb         string                  "json:\"ispb\""
			Issuer       *string                 "json:\"issuer,omitempty\""
			Number       string                  "json:\"number\""
		}{
			Ispb:        api.MockBankISPB,
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountTypeConsents(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
	}

	if c.Rejection != nil {
		resp.Data.Rejection = &Rejection{
			Reason: &ConsentRejectionReason{
				Code:   ConsentRejectionReasonCode(c.Rejection.Code),
				Detail: c.Rejection.Detail,
			},
			RejectedAt:   c.StatusUpdatedAt,
			RejectedBy:   RejectionRejectedBy(c.Rejection.By),
			RejectedFrom: RejectionRejectedFrom(c.Rejection.From),
		}
	}

	if c.Revocation != nil {
		resp.Data.Revocation = &struct {
			Reason *struct {
				Code   ResponseRecurringConsentDataRevocationReasonCode "json:\"code\""
				Detail string                                           "json:\"detail\""
			} "json:\"reason,omitempty\""
			RevokedAt   timeutil.DateTime                                 "json:\"revokedAt\""
			RevokedBy   ResponseRecurringConsentDataRevocationRevokedBy   "json:\"revokedBy\""
			RevokedFrom ResponseRecurringConsentDataRevocationRevokedFrom "json:\"revokedFrom\""
		}{
			Reason: &struct {
				Code   ResponseRecurringConsentDataRevocationReasonCode "json:\"code\""
				Detail string                                           "json:\"detail\""
			}{
				Code:   ResponseRecurringConsentDataRevocationReasonCode(c.Revocation.Code),
				Detail: c.Revocation.Detail,
			},
			RevokedAt:   c.StatusUpdatedAt,
			RevokedBy:   ResponseRecurringConsentDataRevocationRevokedBy(c.Revocation.By),
			RevokedFrom: ResponseRecurringConsentDataRevocationRevokedFrom(c.Revocation.From),
		}
	}

	return AutomaticPaymentsGetRecurringConsentsConsentID200JSONResponse{RecurringConsentsConsentIDJSONResponse(resp)}, nil
}

func (s Server) AutomaticPaymentsGetPixRecurringPayments(ctx context.Context, req AutomaticPaymentsGetPixRecurringPaymentsRequestObject) (AutomaticPaymentsGetPixRecurringPaymentsResponseObject, error) {
	return nil, nil
}

func (s Server) AutomaticPaymentsPostPixRecurringPayments(ctx context.Context, req AutomaticPaymentsPostPixRecurringPaymentsRequestObject) (AutomaticPaymentsPostPixRecurringPaymentsResponseObject, error) {
	return nil, nil
}

func (s Server) AutomaticPaymentsGetPixRecurringPaymentsPaymentID(ctx context.Context, req AutomaticPaymentsGetPixRecurringPaymentsPaymentIDRequestObject) (AutomaticPaymentsGetPixRecurringPaymentsPaymentIDResponseObject, error) {
	return nil, nil
}

func (s Server) AutomaticPaymentsPatchPixRecurringPaymentsPaymentID(ctx context.Context, req AutomaticPaymentsPatchPixRecurringPaymentsPaymentIDRequestObject) (AutomaticPaymentsPatchPixRecurringPaymentsPaymentIDResponseObject, error) {
	return nil, nil
}

func (s Server) AutomaticPaymentsPatchRecurringConsentsConsentID(ctx context.Context, req AutomaticPaymentsPatchRecurringConsentsConsentIDRequestObject) (AutomaticPaymentsPatchRecurringConsentsConsentIDResponseObject, error) {
	return nil, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	api.WriteError(w, r, err)
}
