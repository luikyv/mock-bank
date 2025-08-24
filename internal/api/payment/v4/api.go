//go:generate oapi-codegen -config=./config.yml -package=v4 -o=./api_gen.go ./swagger.yml
package v4

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/luikyv/mock-bank/internal/enrollment"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var _ StrictServerInterface = Server{}

type BankConfig interface {
	Host() string
	ISPB() string
	IBGETownCode() string
	AccountBranch() string
}

type Server struct {
	config             BankConfig
	baseURL            string
	service            payment.Service
	idempotencyService idempotency.Service
	jwtService         jwtutil.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	config BankConfig,
	service payment.Service,
	idempotencyService idempotency.Service,
	jwtService jwtutil.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		config:             config,
		baseURL:            config.Host() + "/open-banking/payments/v4",
		service:            service,
		idempotencyService: idempotencyService,
		jwtService:         jwtService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) Handler() (http.Handler, string) {
	mux := http.NewServeMux()

	jwtMiddleware := middleware.JWT(s.baseURL, s.orgID, s.keystoreHost, s.signer, s.jwtService)
	idempotencyMiddleware := middleware.Idempotency(s.idempotencyService)
	clientCredentialsAuthMiddleware := middleware.Auth(s.op, goidc.GrantClientCredentials, payment.Scope)
	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID)
	swaggerMiddleware, swaggerVersion := middleware.Swagger(GetSwagger, func(err error) api.Error {
		var schemaErr *openapi3.SchemaError
		if errors.As(err, &schemaErr) && schemaErr.SchemaField == "required" {
			return api.NewError("PARAMETRO_NAO_INFORMADO", http.StatusUnprocessableEntity, err.Error())
		}
		return api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error())
	})

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{swaggerMiddleware},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.PaymentsPostConsents)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("POST /consents", handler)

	handler = http.HandlerFunc(wrapper.PaymentsGetConsentsConsentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("GET /consents/{consentId}", handler)

	handler = http.HandlerFunc(wrapper.PaymentsPostPixPayments)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	mux.Handle("POST /pix/payments", handler)

	handler = http.HandlerFunc(wrapper.PaymentsGetPixPaymentsPaymentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("GET /pix/payments/{paymentId}", handler)

	handler = http.HandlerFunc(wrapper.PaymentsPatchPixPaymentsConsentID)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("PATCH /pix/payments/consents/{consentId}", handler)

	handler = http.HandlerFunc(wrapper.PaymentsPatchPixPaymentsPaymentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("PATCH /pix/payments/{paymentId}", handler)

	handler = middleware.FAPIID()(mux)
	return http.StripPrefix("/open-banking/payments/v4", handler), swaggerVersion
}

func (s Server) PaymentsPostConsents(ctx context.Context, req PaymentsPostConsentsRequestObject) (PaymentsPostConsentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c := &payment.Consent{
		UserIdentification:    req.Body.Data.LoggedUser.Document.Identification,
		UserRel:               consent.Relation(req.Body.Data.LoggedUser.Document.Rel),
		ClientID:              clientID,
		CreditorType:          payment.CreditorType(req.Body.Data.Creditor.PersonType),
		CreditorCPFCNPJ:       req.Body.Data.Creditor.CpfCnpj,
		CreditorName:          req.Body.Data.Creditor.Name,
		CreditorAccountISBP:   req.Body.Data.Payment.Details.CreditorAccount.Ispb,
		CreditorAccountNumber: req.Body.Data.Payment.Details.CreditorAccount.Number,
		CreditorAccountType:   payment.AccountType(req.Body.Data.Payment.Details.CreditorAccount.AccountType),
		CreditorAccountIssuer: req.Body.Data.Payment.Details.CreditorAccount.Issuer,
		PaymentType:           payment.Type(req.Body.Data.Payment.Type),
		PaymentCurrency:       req.Body.Data.Payment.Currency,
		PaymentAmount:         req.Body.Data.Payment.Amount,
		PaymentSchedule:       req.Body.Data.Payment.Schedule,
		PaymentDate:           req.Body.Data.Payment.Date,
		LocalInstrument:       payment.LocalInstrument(req.Body.Data.Payment.Details.LocalInstrument),
		IBGETownCode:          req.Body.Data.Payment.IbgeTownCode,
		QRCode:                req.Body.Data.Payment.Details.QrCode,
		Proxy:                 req.Body.Data.Payment.Details.Proxy,
		OrgID:                 orgID,
		Version:               "v4",
	}
	if business := req.Body.Data.BusinessEntity; business != nil {
		rel := consent.Relation(business.Document.Rel)
		c.BusinessIdentification = &business.Document.Identification
		c.BusinessRel = &rel
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
				Amount       string               "json:\"amount\""
				Currency     string               "json:\"currency\""
				Date         *timeutil.BrazilDate "json:\"date,omitempty\""
				Details      Details              "json:\"details\""
				IbgeTownCode *string              "json:\"ibgeTownCode,omitempty\""
				Schedule     *Schedule            "json:\"schedule,omitempty\""
				Type         EnumPaymentType      "json:\"type\""
			} "json:\"payment\""
			Status               EnumAuthorisationStatusType "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime           "json:\"statusUpdateDateTime\""
		}{
			ConsentID:            c.URN(),
			Status:               EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime: c.StatusUpdatedAt,
			CreationDateTime:     c.CreatedAt,
			ExpirationDateTime:   c.ExpiresAt,

			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserIdentification,
					Rel:            string(c.UserRel),
				},
			},
			Creditor: Identification{
				CpfCnpj:    c.CreditorCPFCNPJ,
				Name:       c.CreditorName,
				PersonType: EnumPaymentPersonType(c.CreditorType),
			},
			Payment: struct {
				Amount       string               "json:\"amount\""
				Currency     string               "json:\"currency\""
				Date         *timeutil.BrazilDate "json:\"date,omitempty\""
				Details      Details              "json:\"details\""
				IbgeTownCode *string              "json:\"ibgeTownCode,omitempty\""
				Schedule     *Schedule            "json:\"schedule,omitempty\""
				Type         EnumPaymentType      "json:\"type\""
			}{
				Amount:       c.PaymentAmount,
				Currency:     c.PaymentCurrency,
				Schedule:     c.PaymentSchedule,
				Type:         EnumPaymentType(c.PaymentType),
				IbgeTownCode: c.IBGETownCode,
				Details: Details{
					CreditorAccount: CreditorAccount{
						Ispb:        c.CreditorAccountISBP,
						Number:      c.CreditorAccountNumber,
						AccountType: EnumAccountPaymentsType(c.CreditorAccountType),
						Issuer:      c.CreditorAccountIssuer,
					},
					LocalInstrument: EnumLocalInstrument(c.LocalInstrument),
					QrCode:          c.QRCode,
					Proxy:           c.Proxy,
				},
				Date: c.PaymentDate,
			},
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/consents/" + c.URN()),
	}

	if c.BusinessIdentification != nil {
		rel := *c.BusinessRel
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: *c.BusinessIdentification,
				Rel:            string(rel),
			},
		}
	}

	if c.DebtorAccount != nil {
		branch := s.config.AccountBranch()
		resp.Data.DebtorAccount = &ConsentsDebtorAccount{
			Ispb:        s.config.ISPB(),
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
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
			StatusUpdateDateTime: c.StatusUpdatedAt,
			CreationDateTime:     c.CreatedAt,
			ExpirationDateTime:   c.ExpiresAt,
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
					Identification: c.UserIdentification,
					Rel:            string(c.UserRel),
				},
			},
			Payment: PaymentConsent{
				Amount:   c.PaymentAmount,
				Currency: c.PaymentCurrency,
				Details: Details{
					CreditorAccount: CreditorAccount{
						AccountType: EnumAccountPaymentsType(c.CreditorAccountType),
						Ispb:        c.CreditorAccountISBP,
						Number:      c.CreditorAccountNumber,
						Issuer:      c.CreditorAccountIssuer,
					},
					LocalInstrument: EnumLocalInstrument(c.LocalInstrument),
					QrCode:          c.QRCode,
					Proxy:           c.Proxy,
				},
				Schedule:     c.PaymentSchedule,
				Date:         c.PaymentDate,
				Type:         EnumPaymentType(c.PaymentType),
				IbgeTownCode: c.IBGETownCode,
			},
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/consents/" + c.URN()),
	}

	if c.BusinessIdentification != nil {
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: *c.BusinessIdentification,
				Rel:            string(*c.BusinessRel),
			},
		}
	}

	if c.DebtorAccount != nil {
		branch := s.config.AccountBranch()
		resp.Data.DebtorAccount = &ConsentsDebtorAccount{
			Ispb:        s.config.ISPB(),
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
	}

	if c.Rejection != nil {
		resp.Data.RejectionReason = &ConsentRejectionReason{
			Code:   EnumConsentRejectionReasonType(c.Rejection.Code),
			Detail: c.Rejection.Detail,
		}
	}

	return PaymentsGetConsentsConsentID200JSONResponse{N200PaymentsConsentsConsentIDReadJSONResponse(resp)}, nil
}

func (s Server) PaymentsPostPixPayments(ctx context.Context, req PaymentsPostPixPaymentsRequestObject) (PaymentsPostPixPaymentsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	scopes := ctx.Value(api.CtxKeyScopes).(string)
	var payments []*payment.Payment
	for _, reqPayment := range req.Body.Data {
		p := &payment.Payment{
			Amount:                    reqPayment.Payment.Amount,
			Currency:                  reqPayment.Payment.Currency,
			CreditorAccountISBP:       reqPayment.CreditorAccount.Ispb,
			CreditorAccountIssuer:     reqPayment.CreditorAccount.Issuer,
			CreditorAccountNumber:     reqPayment.CreditorAccount.Number,
			CreditorAccountType:       payment.AccountType(reqPayment.CreditorAccount.AccountType),
			RemittanceInformation:     reqPayment.RemittanceInformation,
			QRCode:                    reqPayment.QrCode,
			Proxy:                     reqPayment.Proxy,
			TransactionIdentification: reqPayment.TransactionIdentification,
			IBGETownCode:              reqPayment.IbgeTownCode,
			Version:                   "v4",
			ClientID:                  clientID,
			OrgID:                     orgID,
		}

		if reqPayment.ConsentID != nil {
			p.ConsentID = uuid.MustParse(strings.TrimPrefix(*reqPayment.ConsentID, payment.ConsentURNPrefix))
		}

		if consentID, _ := payment.ConsentIDFromScopes(scopes); consentID != "" {
			p.ConsentID = uuid.MustParse(consentID)
		}

		if enrollmentID, _ := enrollment.IDFromScopes(scopes); enrollmentID != "" {
			id := uuid.MustParse(enrollmentID)
			p.EnrollmentID = &id
		}

		if reqPayment.EndToEndID != nil {
			p.EndToEndID = *reqPayment.EndToEndID
		}

		if reqPayment.CnpjInitiator != nil {
			p.CNPJInitiator = *reqPayment.CnpjInitiator
		}

		if reqPayment.LocalInstrument != nil {
			p.LocalInstrument = payment.LocalInstrument(*reqPayment.LocalInstrument)
		}

		if reqPayment.AuthorisationFlow != nil {
			authFlow := payment.AuthorisationFlow(*reqPayment.AuthorisationFlow)
			p.AuthorisationFlow = &authFlow
		}

		payments = append(payments, p)
	}

	if err := s.service.CreatePayments(ctx, payments); err != nil {
		return nil, err
	}

	branch := s.config.AccountBranch()
	resp := ResponseCreatePixPayment{
		Links: *api.NewLinks(s.baseURL + "/pix/payments/" + payments[0].ID.String()),
		Meta:  *api.NewMeta(),
	}
	for _, p := range payments {
		consentID := payment.ConsentURN(p.ConsentID)
		respPayment := struct {
			AuthorisationFlow *ResponseCreatePixPaymentDataAuthorisationFlow `json:"authorisationFlow,omitempty"`
			CnpjInitiator     string                                         `json:"cnpjInitiator"`
			ConsentID         *string                                        `json:"consentId,omitempty"`
			CreationDateTime  timeutil.DateTime                              `json:"creationDateTime"`
			CreditorAccount   CreditorAccount                                `json:"creditorAccount"`
			DebtorAccount     DebtorAccount                                  `json:"debtorAccount"`
			EndToEndID        EndToEndID                                     `json:"endToEndId"`
			IbgeTownCode      *string                                        `json:"ibgeTownCode,omitempty"`
			LocalInstrument   EnumLocalInstrument                            `json:"localInstrument"`
			Payment           struct {
				Amount   string `json:"amount"`
				Currency string `json:"currency"`
			} `json:"payment"`
			PaymentID                 string                `json:"paymentId"`
			Proxy                     *string               `json:"proxy,omitempty"`
			RejectionReason           *RejectionReason      `json:"rejectionReason,omitempty"`
			RemittanceInformation     *string               `json:"remittanceInformation,omitempty"`
			Status                    EnumPaymentStatusType `json:"status"`
			StatusUpdateDateTime      timeutil.DateTime     `json:"statusUpdateDateTime"`
			TransactionIdentification *string               `json:"transactionIdentification,omitempty"`
		}{
			PaymentID:        p.ID.String(),
			CnpjInitiator:    p.CNPJInitiator,
			ConsentID:        &consentID,
			CreationDateTime: p.CreatedAt,
			CreditorAccount: CreditorAccount{
				AccountType: EnumAccountPaymentsType(p.CreditorAccountType),
				Ispb:        p.CreditorAccountISBP,
				Issuer:      p.CreditorAccountIssuer,
				Number:      p.CreditorAccountNumber,
			},
			EndToEndID:      p.EndToEndID,
			IbgeTownCode:    p.IBGETownCode,
			LocalInstrument: EnumLocalInstrument(p.LocalInstrument),
			Payment: struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			}{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			Proxy:                     p.Proxy,
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
			DebtorAccount: DebtorAccount{
				AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(p.DebtorAccount.Type)),
				Ispb:        s.config.ISPB(),
				Issuer:      &branch,
				Number:      p.DebtorAccount.Number,
			},
		}

		resp.Data = append(resp.Data, respPayment)
	}

	return PaymentsPostPixPayments201JSONResponse{N201PaymentsInitiationPixPaymentCreatedJSONResponse(resp)}, nil
}

func (s Server) PaymentsPatchPixPaymentsConsentID(ctx context.Context, req PaymentsPatchPixPaymentsConsentIDRequestObject) (PaymentsPatchPixPaymentsConsentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	payments, err := s.service.CancelAll(ctx, req.ConsentID, orgID, consent.Document{
		Identification: req.Body.Data.Cancellation.CancelledBy.Document.Identification,
		Rel:            consent.Relation(req.Body.Data.Cancellation.CancelledBy.Document.Rel),
	})
	if err != nil {
		return nil, err
	}

	resp := ResponsePatchPixConsent{
		Links: *api.NewLinks(s.baseURL + "/pix/payments/consents/" + req.ConsentID),
		Meta:  *api.NewMeta(),
	}
	for _, p := range payments {
		resp.Data = append(resp.Data, struct {
			PaymentID            string            "json:\"paymentId\""
			StatusUpdateDateTime timeutil.DateTime "json:\"statusUpdateDateTime\""
		}{
			PaymentID:            p.ID.String(),
			StatusUpdateDateTime: p.StatusUpdatedAt,
		})
	}

	return PaymentsPatchPixPaymentsConsentID200JSONResponse{N200PatchPixConsentsJSONResponse(resp)}, nil
}

func (s Server) PaymentsGetPixPaymentsPaymentID(ctx context.Context, req PaymentsGetPixPaymentsPaymentIDRequestObject) (PaymentsGetPixPaymentsPaymentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	p, err := s.service.Payment(ctx, req.PaymentID, orgID)
	if err != nil {
		return nil, err
	}

	branch := s.config.AccountBranch()
	resp := ResponsePixPayment{
		Data: ResponsePixPaymentData{
			PaymentID:        p.ID.String(),
			CnpjInitiator:    p.CNPJInitiator,
			ConsentID:        payment.ConsentURN(p.ConsentID),
			CreationDateTime: p.CreatedAt,
			CreditorAccount: CreditorAccount{
				AccountType: EnumAccountPaymentsType(p.CreditorAccountType),
				Ispb:        p.CreditorAccountISBP,
				Issuer:      p.CreditorAccountIssuer,
				Number:      p.CreditorAccountNumber,
			},
			EndToEndID:      p.EndToEndID,
			IbgeTownCode:    p.IBGETownCode,
			LocalInstrument: EnumLocalInstrument(p.LocalInstrument),
			Payment: struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			}{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			Proxy:                     p.Proxy,
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
			DebtorAccount: DebtorAccount{
				AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(p.DebtorAccount.Type)),
				Ispb:        s.config.ISPB(),
				Issuer:      &branch,
				Number:      p.DebtorAccount.Number,
			},
		},
		Links: *api.NewLinks(s.baseURL + "/pix/payments/" + p.ID.String()),
		Meta:  *api.NewMeta(),
	}

	if p.Rejection != nil {
		resp.Data.RejectionReason = &RejectionReasonGetPix{
			Code:   EnumRejectionReasonTypeGetPix(p.Rejection.Code),
			Detail: p.Rejection.Detail,
		}
	}

	if p.Cancellation != nil {
		cancellation := &PixPaymentCancellation{
			CancelledAt:   p.Cancellation.At,
			CancelledFrom: EnumPaymentCancellationFromType(p.Cancellation.From),
			Reason:        EnumPaymentCancellationReasonType(p.Cancellation.Reason),
		}
		cancellation.CancelledBy.Document.Identification = p.Cancellation.By
		cancellation.CancelledBy.Document.Rel = "CPF"
		resp.Data.Cancellation = cancellation
	}

	return PaymentsGetPixPaymentsPaymentID200JSONResponse{N200PaymentsInitiationPixPaymentIDReadJSONResponse(resp)}, nil
}

func (s Server) PaymentsPatchPixPaymentsPaymentID(ctx context.Context, req PaymentsPatchPixPaymentsPaymentIDRequestObject) (PaymentsPatchPixPaymentsPaymentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	p, err := s.service.Cancel(ctx, string(req.PaymentID), orgID, consent.Document{
		Identification: req.Body.Data.Cancellation.CancelledBy.Document.Identification,
		Rel:            consent.Relation(req.Body.Data.Cancellation.CancelledBy.Document.Rel),
	})
	if err != nil {
		return nil, err
	}

	branch := s.config.AccountBranch()
	resp := ResponsePatchPixPayment{
		Data: ResponsePatchPixPaymentData{
			PaymentID:        p.ID.String(),
			CnpjInitiator:    p.CNPJInitiator,
			ConsentID:        payment.ConsentURN(p.ConsentID),
			CreationDateTime: p.CreatedAt,
			CreditorAccount: CreditorAccount{
				AccountType: EnumAccountPaymentsType(p.CreditorAccountType),
				Ispb:        p.CreditorAccountISBP,
				Issuer:      p.CreditorAccountIssuer,
				Number:      p.CreditorAccountNumber,
			},
			EndToEndID:      p.EndToEndID,
			IbgeTownCode:    p.IBGETownCode,
			LocalInstrument: EnumLocalInstrument(p.LocalInstrument),
			Payment: struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			}{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			Proxy:                     p.Proxy,
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
			DebtorAccount: DebtorAccount{
				AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(p.DebtorAccount.Type)),
				Ispb:        s.config.ISPB(),
				Issuer:      &branch,
				Number:      p.DebtorAccount.Number,
			},
		},
		Links: *api.NewLinks(s.baseURL + "/pix/payments/" + p.ID.String()),
		Meta:  *api.NewMeta(),
	}

	if p.Cancellation != nil {
		cancellation := PatchPixPaymentCancellation{
			CancelledAt:   p.Cancellation.At,
			CancelledFrom: EnumPaymentCancellationFromType(p.Cancellation.From),
			Reason:        EnumPaymentCancellationReasonType(p.Cancellation.Reason),
		}
		cancellation.CancelledBy.Document.Identification = p.Cancellation.By
		cancellation.CancelledBy.Document.Rel = "CPF"
		resp.Data.Cancellation = cancellation
	}

	return PaymentsPatchPixPaymentsPaymentID200JSONResponse{N200PatchPixPaymentsJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, payment.ErrInvalidEndToEndID) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrCreditorAndDebtorAccountsAreEqual) {
		api.WriteError(w, r, api.NewError("DETALHE_PAGAMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidPayment) {
		api.WriteError(w, r, api.NewError("DETALHE_PAGAMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrPaymentDoesNotMatchConsent) {
		api.WriteError(w, r, api.NewError("PAGAMENTO_DIVERGENTE_CONSENTIMENTO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidDate) {
		api.WriteError(w, r, api.NewError("DATA_PAGAMENTO_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrMissingValue) {
		api.WriteError(w, r, api.NewError("PARAMETRO_NAO_INFORMADO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrCancelNotAllowed) {
		api.WriteError(w, r, api.NewError("PAGAMENTO_NAO_PERMITE_CANCELAMENTO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidConsentStatus) {
		api.WriteError(w, r, api.NewError("CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidData) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrConsentPartiallyAccepted) {
		api.WriteError(w, r, api.NewError("CONSENTIMENTO_PENDENTE_AUTORIZACAO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidPaymentMethod) {
		api.WriteError(w, r, api.NewError("FORMA_PAGAMENTO_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.As(err, &errorutil.Error{}) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}
