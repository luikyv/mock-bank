//go:generate oapi-codegen -config=./config.yml -package=paymentv4 -o=./api_gen.go ./swagger.yml
package paymentv4

import (
	"context"
	"crypto"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/errorutil"
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
	service            payment.Service
	idempotencyService idempotency.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	host string,
	service payment.Service,
	idempotencyService idempotency.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		baseURL:            host + "/open-banking/payments/v4",
		service:            service,
		idempotencyService: idempotencyService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	paymentMux := http.NewServeMux()

	jwtMiddleware := jwtutil.Middleware(s.baseURL, s.orgID, s.keystoreHost, s.signer)
	idempotencyMiddleware := idempotency.Middleware(s.idempotencyService)
	clientCredentialsAuthMiddleware := oidc.AuthMiddleware(s.op, payment.Scope)
	authCodeAuthMiddleware := oidc.AuthMiddleware(s.op, goidc.ScopeOpenID, consent.ScopeID)
	swaggerMiddleware := api.SwaggerMiddleware(GetSwagger, "PARAMETRO_INVALIDO")

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{
			swaggerMiddleware,
			api.FAPIIDMiddleware(nil),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.PaymentsPostConsents)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	paymentMux.Handle("POST /consents", handler)

	handler = http.HandlerFunc(wrapper.PaymentsGetConsentsConsentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	paymentMux.Handle("GET /consents/{consentId}", handler)

	handler = http.HandlerFunc(wrapper.PaymentsPostPixPayments)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	paymentMux.Handle("POST /pix/payments", handler)

	handler = http.HandlerFunc(wrapper.PaymentsGetPixPaymentsPaymentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	paymentMux.Handle("GET /pix/payments/{paymentId}", handler)

	handler = http.HandlerFunc(wrapper.PaymentsPatchPixPaymentsConsentID)
	handler = jwtMiddleware(handler)
	handler = idempotencyMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	paymentMux.Handle("PATCH /pix/payments/consents/{consentId}", handler)

	handler = http.HandlerFunc(wrapper.PaymentsPatchPixPaymentsPaymentID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	paymentMux.Handle("PATCH /pix/payments/{paymentId}", handler)

	mux.Handle("/open-banking/payments/v4/", http.StripPrefix("/open-banking/payments/v4", paymentMux))
}

func (s Server) PaymentsPostConsents(ctx context.Context, req PaymentsPostConsentsRequestObject) (PaymentsPostConsentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c := &payment.Consent{
		UserCPF:  req.Body.Data.LoggedUser.Document.Identification,
		ClientID: clientID,
		Creditor: payment.Creditor{
			Type:    payment.CreditorType(req.Body.Data.Creditor.PersonType),
			CPFCNPJ: req.Body.Data.Creditor.CpfCnpj,
			Name:    req.Body.Data.Creditor.Name,
		},
		CreditorAccount: payment.CreditorAccount{
			ISBP:   req.Body.Data.Payment.Details.CreditorAccount.Ispb,
			Number: req.Body.Data.Payment.Details.CreditorAccount.Number,
			Type:   payment.AccountType(req.Body.Data.Payment.Details.CreditorAccount.AccountType),
			Issuer: req.Body.Data.Payment.Details.CreditorAccount.Issuer,
		},
		PaymentType:     payment.Type(req.Body.Data.Payment.Type),
		PaymentCurrency: req.Body.Data.Payment.Currency,
		PaymentAmount:   req.Body.Data.Payment.Amount,
		PaymentSchedule: req.Body.Data.Payment.Schedule,
		PaymentDate:     req.Body.Data.Payment.Date,
		LocalInstrument: payment.LocalInstrument(req.Body.Data.Payment.Details.LocalInstrument),
		IBGETownCode:    req.Body.Data.Payment.IbgeTownCode,
		QRCode:          req.Body.Data.Payment.Details.QrCode,
		Proxy:           req.Body.Data.Payment.Details.Proxy,
		OrgID:           orgID,
	}
	if req.Body.Data.BusinessEntity != nil {
		c.BusinessCNPJ = &req.Body.Data.BusinessEntity.Document.Identification
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
					Identification: c.UserCPF,
					Rel:            "CPF",
				},
			},
			Creditor: Identification{
				CpfCnpj:    c.Creditor.CPFCNPJ,
				Name:       c.Creditor.Name,
				PersonType: EnumPaymentPersonType(c.Creditor.Type),
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
						Ispb:        c.CreditorAccount.ISBP,
						Number:      c.CreditorAccount.Number,
						AccountType: EnumAccountPaymentsType(c.CreditorAccount.Type),
						Issuer:      c.CreditorAccount.Issuer,
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
		resp.Data.DebtorAccount = &ConsentsDebtorAccount{
			Ispb:        api.MockBankISPB,
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
				CpfCnpj:    c.Creditor.CPFCNPJ,
				Name:       c.Creditor.Name,
				PersonType: EnumPaymentPersonType(c.Creditor.Type),
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
				Amount:   c.PaymentAmount,
				Currency: c.PaymentCurrency,
				Details: Details{
					CreditorAccount: CreditorAccount{
						AccountType: EnumAccountPaymentsType(c.CreditorAccount.Type),
						Ispb:        c.CreditorAccount.ISBP,
						Number:      c.CreditorAccount.Number,
						Issuer:      c.CreditorAccount.Issuer,
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
		resp.Data.DebtorAccount = &ConsentsDebtorAccount{
			Ispb:        api.MockBankISPB,
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
	consentID, _ := consent.IDFromScopes(ctx.Value(api.CtxKeyScopes).(string))
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	var payments []*payment.Payment
	for _, reqPayment := range req.Body.Data {
		p := &payment.Payment{
			EndToEndID:      reqPayment.EndToEndID,
			LocalInstrument: payment.LocalInstrument(reqPayment.LocalInstrument),
			Amount:          reqPayment.Payment.Amount,
			Currency:        reqPayment.Payment.Currency,
			CreditorAccount: payment.CreditorAccount{
				ISBP:   reqPayment.CreditorAccount.Ispb,
				Issuer: reqPayment.CreditorAccount.Issuer,
				Number: reqPayment.CreditorAccount.Number,
				Type:   payment.AccountType(reqPayment.CreditorAccount.AccountType),
			},
			RemittanceInformation:     reqPayment.RemittanceInformation,
			QRCode:                    reqPayment.QrCode,
			Proxy:                     reqPayment.Proxy,
			CNPJInitiator:             reqPayment.CnpjInitiator,
			TransactionIdentification: reqPayment.TransactionIdentification,
			IBGETownCode:              reqPayment.IbgeTownCode,
			ClientID:                  clientID,
			OrgID:                     orgID,
		}

		if consentID != "" {
			p.ConsentID = uuid.MustParse(consentID)
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

	branch := account.DefaultBranch
	resp := ResponseCreatePixPayment{
		Links: *api.NewLinks(s.baseURL + "/pix/payments/" + payments[0].ID.String()),
		Meta:  *api.NewMeta(),
	}
	for _, p := range payments {
		consentID := consent.URN(p.ConsentID)
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
				AccountType: EnumAccountPaymentsType(p.CreditorAccount.Type),
				Ispb:        p.CreditorAccount.ISBP,
				Issuer:      p.CreditorAccount.Issuer,
				Number:      p.CreditorAccount.Number,
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
				Ispb:        api.MockBankISPB,
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
	payments, err := s.service.CancelAll(ctx, req.ConsentID, orgID, payment.Document{
		Identification: req.Body.Data.Cancellation.CancelledBy.Document.Identification,
		Rel:            req.Body.Data.Cancellation.CancelledBy.Document.Rel,
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

	branch := account.DefaultBranch
	resp := ResponsePixPayment{
		Data: ResponsePixPaymentData{
			PaymentID:        p.ID.String(),
			CnpjInitiator:    p.CNPJInitiator,
			ConsentID:        consent.URN(p.ConsentID),
			CreationDateTime: p.CreatedAt,
			CreditorAccount: CreditorAccount{
				AccountType: EnumAccountPaymentsType(p.CreditorAccount.Type),
				Ispb:        p.CreditorAccount.ISBP,
				Issuer:      p.CreditorAccount.Issuer,
				Number:      p.CreditorAccount.Number,
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
				Ispb:        api.MockBankISPB,
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
	p, err := s.service.Cancel(ctx, string(req.PaymentID), orgID, payment.Document{
		Identification: req.Body.Data.Cancellation.CancelledBy.Document.Identification,
		Rel:            req.Body.Data.Cancellation.CancelledBy.Document.Rel,
	})
	if err != nil {
		return nil, err
	}

	branch := account.DefaultBranch
	resp := ResponsePatchPixPayment{
		Data: ResponsePatchPixPaymentData{
			PaymentID:        p.ID.String(),
			CnpjInitiator:    p.CNPJInitiator,
			ConsentID:        consent.URN(p.ConsentID),
			CreationDateTime: p.CreatedAt,
			CreditorAccount: CreditorAccount{
				AccountType: EnumAccountPaymentsType(p.CreditorAccount.Type),
				Ispb:        p.CreditorAccount.ISBP,
				Issuer:      p.CreditorAccount.Issuer,
				Number:      p.CreditorAccount.Number,
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
				Ispb:        api.MockBankISPB,
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

	if errors.Is(err, payment.ErrConsentNotAuthorized) {
		api.WriteError(w, r, api.NewError("CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidData) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.As(err, &errorutil.Error{}) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}
