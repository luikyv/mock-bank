//go:generate oapi-codegen -config=./config.yml -package=paymentv4 -o=./api_gen.go ./swagger.yml
package paymentv4

import (
	"context"
	"crypto"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/jwtutil"
	"github.com/luiky/mock-bank/internal/oidc"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/provider"
	netmiddleware "github.com/oapi-codegen/nethttp-middleware"
)

var _ StrictServerInterface = Server{}

type Server struct {
	baseURL      string
	service      payment.Service
	op           *provider.Provider
	keystoreHost string
	orgID        string
	signer       crypto.Signer
}

func NewServer(
	host string,
	service payment.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		baseURL:      host + "/open-banking/payments/v4",
		service:      service,
		op:           op,
		keystoreHost: keystoreHost,
		orgID:        orgID,
		signer:       signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	paymentMux := http.NewServeMux()

	spec, err := GetSwagger()
	if err != nil {
		panic(err)
	}
	swaggerMiddleware := netmiddleware.OapiRequestValidatorWithOptions(spec, &netmiddleware.Options{
		DoNotValidateServers: true,
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
		ErrorHandler: func(w http.ResponseWriter, message string, _ int) {
			api.WriteError(w, nil, api.NewError("INVALID_REQUEST", http.StatusBadRequest, message))
		},
	})

	strictHandler := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeResponseError(w, r, err)
		},
	})
	wrapper := ServerInterfaceWrapper{
		Handler: strictHandler,
		HandlerMiddlewares: []MiddlewareFunc{
			swaggerMiddleware,
			api.FAPIIDMiddleware(nil),
			jwtutil.Middleware(s.baseURL, s.orgID, s.keystoreHost, s.signer),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.PaymentsPostConsents)
	handler = oidc.AuthMiddleware(handler, s.op, payment.Scope)
	paymentMux.Handle("POST /consents", handler)

	handler = http.HandlerFunc(wrapper.PaymentsGetConsentsConsentID)
	handler = oidc.AuthMiddleware(handler, s.op, payment.Scope)
	paymentMux.Handle("GET /consents/{consentId}", handler)

	mux.Handle("/open-banking/payments/v4/", http.StripPrefix("/open-banking/payments/v4", paymentMux))
}

func (s Server) PaymentsPostConsents(ctx context.Context, req PaymentsPostConsentsRequestObject) (PaymentsPostConsentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c := &payment.Consent{
		UserCPF:               req.Body.Data.LoggedUser.Document.Identification,
		ClientID:              clientID,
		CreditorType:          payment.CreditorType(req.Body.Data.Creditor.PersonType),
		CreditorCPFCNPJ:       req.Body.Data.Creditor.CpfCnpj,
		CreditorName:          req.Body.Data.Creditor.Name,
		CreditorAccountISBP:   req.Body.Data.Payment.Details.CreditorAccount.Ispb,
		CreditorAccountNumber: req.Body.Data.Payment.Details.CreditorAccount.Number,
		CreditorAccountType:   payment.AccountType(req.Body.Data.Payment.Details.CreditorAccount.AccountType),
		PaymentType:           payment.Type(req.Body.Data.Payment.Type),
		Currency:              req.Body.Data.Payment.Currency,
		Amount:                req.Body.Data.Payment.Amount,
		PaymentSchedule:       req.Body.Data.Payment.Schedule,
		LocalInstrument:       payment.LocalInstrument(req.Body.Data.Payment.Details.LocalInstrument),
		OrgID:                 orgID,
	}
	if req.Body.Data.BusinessEntity != nil {
		c.BusinessCNPJ = req.Body.Data.BusinessEntity.Document.Identification
	}
	if req.Body.Data.Payment.Details.CreditorAccount.Issuer != nil {
		c.CreditorAccountIssuer = *req.Body.Data.Payment.Details.CreditorAccount.Issuer
	}
	if req.Body.Data.Payment.IbgeTownCode != nil {
		c.IBGETownCode = *req.Body.Data.Payment.IbgeTownCode
	}
	if req.Body.Data.Payment.Details.QrCode != nil {
		c.QRCode = *req.Body.Data.Payment.Details.QrCode
	}
	if req.Body.Data.Payment.Details.Proxy != nil {
		c.Proxy = *req.Body.Data.Payment.Details.Proxy
	}
	if req.Body.Data.Payment.Date != nil {
		c.PaymentDate = &req.Body.Data.Payment.Date.Time
	}

	var debtorAccount *payment.DebtorAccount
	if req.Body.Data.DebtorAccount != nil {
		debtorAccount = &payment.DebtorAccount{
			ISBP:   req.Body.Data.DebtorAccount.Ispb,
			Number: req.Body.Data.DebtorAccount.Number,
			Type:   payment.AccountType(req.Body.Data.DebtorAccount.AccountType),
		}
		if req.Body.Data.DebtorAccount.Issuer != nil {
			debtorAccount.Issuer = *req.Body.Data.DebtorAccount.Issuer
		}
	}
	if err := s.service.CreateConsent(ctx, c, debtorAccount); err != nil {
		return nil, err
	}

	resp := ResponseCreatePaymentConsent{
		Data: struct {
			BusinessEntity     *BusinessEntity        "json:\"businessEntity,omitempty\""
			ConsentID          string                 "json:\"consentId\""
			CreationDateTime   timeutil.DateTime      "json:\"creationDateTime\""
			Creditor           Identification         "json:\"creditor\""
			DebtorAccount      *ConsentsDebtorAccount "json:\"debtorAccount,omitempty\""
			ExpirationDateTime timeutil.DateTime      "json:\"expirationDateTime\""
			LoggedUser         LoggedUser             "json:\"loggedUser\""
			Payment            struct {
				Amount       string          "json:\"amount\""
				Currency     string          "json:\"currency\""
				Date         *timeutil.Date  "json:\"date,omitempty\""
				Details      Details         "json:\"details\""
				IbgeTownCode *string         "json:\"ibgeTownCode,omitempty\""
				Schedule     *Schedule       "json:\"schedule,omitempty\""
				Type         EnumPaymentType "json:\"type\""
			} "json:\"payment\""
			Status               EnumAuthorisationStatusType "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime           "json:\"statusUpdateDateTime\""
		}{
			ConsentID:            c.URN(),
			Status:               EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime: timeutil.NewDateTime(c.StatusUpdatedAt),
			CreationDateTime:     timeutil.NewDateTime(c.CreatedAt),
			ExpirationDateTime:   timeutil.NewDateTime(c.ExpiresAt),
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserCPF,
					Rel:            "CPF",
				},
			},
			Creditor: Identification{
				CpfCnpj:    c.CreditorCPFCNPJ,
				Name:       c.CreditorName,
				PersonType: EnumPaymentPersonType(c.CreditorType),
			},
			Payment: struct {
				Amount       string          "json:\"amount\""
				Currency     string          "json:\"currency\""
				Date         *timeutil.Date  "json:\"date,omitempty\""
				Details      Details         "json:\"details\""
				IbgeTownCode *string         "json:\"ibgeTownCode,omitempty\""
				Schedule     *Schedule       "json:\"schedule,omitempty\""
				Type         EnumPaymentType "json:\"type\""
			}{
				Amount:   c.Amount,
				Currency: c.Currency,
				Schedule: c.PaymentSchedule,
				Type:     EnumPaymentType(c.PaymentType),
				Details: Details{
					CreditorAccount: CreditorAccount{
						Ispb:        c.CreditorAccountISBP,
						Number:      c.CreditorAccountNumber,
						AccountType: EnumAccountPaymentsType(c.CreditorAccountType),
					},
					LocalInstrument: EnumLocalInstrument(c.LocalInstrument),
				},
			},
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/consents/" + c.URN()),
	}

	if c.BusinessCNPJ != "" {
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: c.BusinessCNPJ,
				Rel:            "CNPJ",
			},
		}
	}

	if c.DebtorAccount != nil {
		branch := account.DefaultBranch
		resp.Data.DebtorAccount = &ConsentsDebtorAccount{
			Ispb:        "",
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
	}

	if c.PaymentDate != nil {
		d := timeutil.NewDate(*c.PaymentDate)
		resp.Data.Payment.Date = &d
	}

	if c.IBGETownCode != "" {
		resp.Data.Payment.IbgeTownCode = &c.IBGETownCode
	}

	if c.QRCode != "" {
		resp.Data.Payment.Details.QrCode = &c.QRCode
	}

	if c.Proxy != "" {
		resp.Data.Payment.Details.Proxy = &c.Proxy
	}

	if c.CreditorAccountIssuer != "" {
		resp.Data.Payment.Details.CreditorAccount.Issuer = &c.CreditorAccountIssuer
	}

	return PaymentsPostConsents201JSONResponse{N201PaymentsConsentsConsentCreatedJSONResponse(resp)}, nil
}

func (s Server) PaymentsGetConsentsConsentID(ctx context.Context, req PaymentsGetConsentsConsentIDRequestObject) (PaymentsGetConsentsConsentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c, err := s.service.Consent(ctx, req.ConsentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponsePaymentConsent{
		Data: struct {
			BusinessEntity       *BusinessEntity             "json:\"businessEntity,omitempty\""
			ConsentID            string                      "json:\"consentId\""
			CreationDateTime     timeutil.DateTime           "json:\"creationDateTime\""
			Creditor             Identification              "json:\"creditor\""
			DebtorAccount        *ConsentsDebtorAccount      "json:\"debtorAccount,omitempty\""
			ExpirationDateTime   timeutil.DateTime           "json:\"expirationDateTime\""
			LoggedUser           LoggedUser                  "json:\"loggedUser\""
			Payment              PaymentConsent              "json:\"payment\""
			RejectionReason      *ConsentRejectionReason     "json:\"rejectionReason,omitempty\""
			Status               EnumAuthorisationStatusType "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime           "json:\"statusUpdateDateTime\""
		}{
			ConsentID:            c.URN(),
			Status:               EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime: timeutil.NewDateTime(c.StatusUpdatedAt),
			CreationDateTime:     timeutil.NewDateTime(c.CreatedAt),
			ExpirationDateTime:   timeutil.NewDateTime(c.ExpiresAt),
			Creditor: Identification{
				CpfCnpj:    c.CreditorCPFCNPJ,
				Name:       c.CreditorName,
				PersonType: EnumPaymentPersonType(c.CreditorType),
			},
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserCPF,
					Rel:            "CPF",
				},
			},
			Payment: PaymentConsent{
				Amount:   c.Amount,
				Currency: c.Currency,
				Details: Details{
					CreditorAccount: CreditorAccount{
						AccountType: EnumAccountPaymentsType(c.PaymentType),
						Ispb:        c.CreditorAccountISBP,
						Number:      c.CreditorAccountNumber,
					},
					LocalInstrument: EnumLocalInstrument(c.LocalInstrument),
				},
				Schedule: c.PaymentSchedule,
				Type:     EnumPaymentType(c.PaymentType),
			},
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/consents/" + c.URN()),
	}

	if c.BusinessCNPJ != "" {
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: c.BusinessCNPJ,
				Rel:            "CNPJ",
			},
		}
	}

	if c.DebtorAccount != nil {
		branch := account.DefaultBranch
		resp.Data.DebtorAccount = &ConsentsDebtorAccount{
			Ispb:        "",
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
	}

	if c.PaymentDate != nil {
		d := timeutil.NewDate(*c.PaymentDate)
		resp.Data.Payment.Date = &d
	}

	if c.IBGETownCode != "" {
		resp.Data.Payment.IbgeTownCode = &c.IBGETownCode
	}

	if c.QRCode != "" {
		resp.Data.Payment.Details.QrCode = &c.QRCode
	}

	if c.Proxy != "" {
		resp.Data.Payment.Details.Proxy = &c.Proxy
	}

	if c.CreditorAccountIssuer != "" {
		resp.Data.Payment.Details.CreditorAccount.Issuer = &c.CreditorAccountIssuer
	}

	return PaymentsGetConsentsConsentID200JSONResponse{N200PaymentsConsentsConsentIDReadJSONResponse(resp)}, nil
}

func (s Server) PaymentsPostPixPayments(ctx context.Context, request PaymentsPostPixPaymentsRequestObject) (PaymentsPostPixPaymentsResponseObject, error) {
	return nil, nil
}

func (s Server) PaymentsPatchPixPaymentsConsentID(ctx context.Context, request PaymentsPatchPixPaymentsConsentIDRequestObject) (PaymentsPatchPixPaymentsConsentIDResponseObject, error) {
	return nil, nil
}

func (s Server) PaymentsGetPixPaymentsPaymentID(ctx context.Context, request PaymentsGetPixPaymentsPaymentIDRequestObject) (PaymentsGetPixPaymentsPaymentIDResponseObject, error) {
	return nil, nil
}

func (s Server) PaymentsPatchPixPaymentsPaymentID(ctx context.Context, request PaymentsPatchPixPaymentsPaymentIDRequestObject) (PaymentsPatchPixPaymentsPaymentIDResponseObject, error) {
	return nil, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	api.WriteError(w, r, err)
}
