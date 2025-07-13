//go:generate oapi-codegen -config=./config.yml -package=autopaymentv2 -o=./api_gen.go ./swagger.yml
package autopaymentv2

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/enrollment"
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
	service            autopayment.Service
	idempotencyService idempotency.Service
	jwtService         jwtutil.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	config BankConfig,
	service autopayment.Service,
	idempotencyService idempotency.Service,
	jwtService jwtutil.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		config:             config,
		baseURL:            config.Host() + "/open-banking/automatic-payments/v2",
		service:            service,
		idempotencyService: idempotencyService,
		jwtService:         jwtService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	autoPaymentMux := http.NewServeMux()

	jwtMiddleware := middleware.JWT(s.baseURL, s.orgID, s.keystoreHost, s.signer, s.jwtService)
	idempotencyMiddleware := middleware.Idempotency(s.idempotencyService)
	clientCredentialsAuthMiddleware := middleware.Auth(s.op, goidc.GrantClientCredentials, autopayment.Scope)
	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID)
	swaggerMiddleware, swaggerVersion := middleware.Swagger(GetSwagger, func(err error) api.Error {
		if strings.Contains(err.Error(), "is missing") {
			return api.NewError("PARAMETRO_NAO_INFORMADO", http.StatusUnprocessableEntity, err.Error())
		}
		return api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error())
	})
	xvMiddleware := middleware.Version(swaggerVersion)

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{
			xvMiddleware,
			swaggerMiddleware,
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

	handler = http.HandlerFunc(wrapper.AutomaticPaymentsPatchPixRecurringPaymentsPaymentID)

	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	autoPaymentMux.Handle("PATCH /pix/recurring-payments/{recurringPaymentId}", handler)

	handler = middleware.FAPIID()(autoPaymentMux)
	mux.Handle("/open-banking/automatic-payments/v2/", http.StripPrefix("/open-banking/automatic-payments/v2", handler))
}

func (s Server) AutomaticPaymentsPostRecurringConsents(ctx context.Context, req AutomaticPaymentsPostRecurringConsentsRequestObject) (AutomaticPaymentsPostRecurringConsentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c := &autopayment.Consent{
		UserIdentification: req.Body.Data.LoggedUser.Document.Identification,
		UserRel:            consent.Relation(req.Body.Data.LoggedUser.Document.Rel),
		ExpiresAt:          req.Body.Data.ExpirationDateTime,
		AdditionalInfo:     req.Body.Data.AdditionalInformation,
		Configuration:      req.Body.Data.RecurringConfiguration,
		Version:            "v2",
		ClientID:           clientID,
		OrgID:              orgID,
	}
	if business := req.Body.Data.BusinessEntity; business != nil {
		c.BusinessIdentification = &business.Document.Identification
		c.BusinessIdentification = &business.Document.Rel
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
					Identification: c.UserIdentification,
					Rel:            string(c.UserRel),
				},
			},
			RecurringConfiguration: c.Configuration,
			RecurringConsentID:     c.URN(),
			Status:                 EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime:   c.StatusUpdatedAt,
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
		resp.Data.DebtorAccount = &struct {
			AccountType EnumAccountTypeConsents "json:\"accountType\""
			Ispb        string                  "json:\"ispb\""
			Issuer      *string                 "json:\"issuer,omitempty\""
			Number      string                  "json:\"number\""
		}{
			Ispb:        s.config.ISPB(),
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
			RiskSignals:            c.RiskSignals,
			Status:                 EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime:   c.StatusUpdatedAt,
			UpdatedAtDateTime:      &c.UpdatedAt,
			RecurringConfiguration: c.Configuration,
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserIdentification,
					Rel:            string(c.UserRel),
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
		ibgeTownCode := s.config.IBGETownCode()
		resp.Data.DebtorAccount = &struct {
			AccountType  EnumAccountTypeConsents "json:\"accountType\""
			IbgeTownCode *string                 "json:\"ibgeTownCode,omitempty\""
			Ispb         string                  "json:\"ispb\""
			Issuer       *string                 "json:\"issuer,omitempty\""
			Number       string                  "json:\"number\""
		}{
			Ispb:         s.config.ISPB(),
			IbgeTownCode: &ibgeTownCode,
			Issuer:       &branch,
			Number:       c.DebtorAccount.Number,
			AccountType:  EnumAccountTypeConsents(payment.ConvertAccountType(c.DebtorAccount.Type)),
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

func (s Server) AutomaticPaymentsPatchRecurringConsentsConsentID(ctx context.Context, req AutomaticPaymentsPatchRecurringConsentsConsentIDRequestObject) (AutomaticPaymentsPatchRecurringConsentsConsentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)

	var c *autopayment.Consent
	var err error
	if action, _ := req.Body.Data.AsConsentRejection(); action.Status != nil && *action.Status == ConsentRejectionStatusREJECTED {
		c, err = s.service.RejectConsentByID(ctx, req.RecurringConsentID, orgID, autopayment.ConsentRejection{
			By:     autopayment.TerminatedBy(action.Rejection.RejectedBy),
			From:   autopayment.TerminatedFrom(action.Rejection.RejectedFrom),
			Code:   autopayment.ConsentRejectionCode(action.Rejection.Reason.Code),
			Detail: action.Rejection.Reason.Detail,
		})
	} else if action, _ := req.Body.Data.AsConsentRevocation(); action.Status != nil && *action.Status == REVOKED {
		c, err = s.service.RevokeConsent(ctx, req.RecurringConsentID, orgID, autopayment.ConsentRevocation{
			By:     autopayment.TerminatedBy(action.Revocation.RevokedBy),
			From:   autopayment.TerminatedFrom(action.Revocation.RevokedFrom),
			Code:   autopayment.ConsentRevocationCode(action.Revocation.Reason.Code),
			Detail: action.Revocation.Reason.Detail,
		})
	} else {
		action, _ := req.Body.Data.AsConsentEdition()
		c, err = s.service.EditConsent(ctx, req.RecurringConsentID, orgID, action)
	}
	if err != nil {
		return nil, err
	}

	resp := ResponseRecurringConsentPatch{
		Data: struct {
			AdditionalInformation *string              "json:\"additionalInformation,omitempty\""
			ApprovalDueDate       *timeutil.BrazilDate "json:\"approvalDueDate,omitempty\""
			AuthorisedAtDateTime  *timeutil.DateTime   "json:\"authorisedAtDateTime,omitempty\""
			BusinessEntity        *BusinessEntity      "json:\"businessEntity,omitempty\""
			CreationDateTime      timeutil.DateTime    "json:\"creationDateTime\""
			Creditors             Creditors            "json:\"creditors\""
			DebtorAccount         *struct {
				AccountType EnumAccountTypeConsents "json:\"accountType\""
				Ispb        string                  "json:\"ispb\""
				Issuer      *string                 "json:\"issuer,omitempty\""
				Number      string                  "json:\"number\""
			} "json:\"debtorAccount,omitempty\""
			ExpirationDateTime     *timeutil.DateTime     "json:\"expirationDateTime,omitempty\""
			LoggedUser             *LoggedUser            "json:\"loggedUser,omitempty\""
			RecurringConfiguration RecurringConfiguration "json:\"recurringConfiguration\""
			RecurringConsentID     string                 "json:\"recurringConsentId\""
			Rejection              *struct {
				Reason       *ConsentRejectionReason                                "json:\"reason,omitempty\""
				RejectedAt   timeutil.DateTime                                      "json:\"rejectedAt\""
				RejectedBy   ResponseRecurringConsentPatchDataRejectionRejectedBy   "json:\"rejectedBy\""
				RejectedFrom ResponseRecurringConsentPatchDataRejectionRejectedFrom "json:\"rejectedFrom\""
			} "json:\"rejection,omitempty\""
			Revocation *struct {
				Reason *struct {
					Code   ResponseRecurringConsentPatchDataRevocationReasonCode "json:\"code\""
					Detail string                                                "json:\"detail\""
				} "json:\"reason,omitempty\""
				RevokedAt   timeutil.DateTime                                      "json:\"revokedAt\""
				RevokedBy   ResponseRecurringConsentPatchDataRevocationRevokedBy   "json:\"revokedBy\""
				RevokedFrom ResponseRecurringConsentPatchDataRevocationRevokedFrom "json:\"revokedFrom\""
			} "json:\"revocation,omitempty\""
			RiskSignals          *RiskSignalsConsents        "json:\"riskSignals,omitempty\""
			Status               EnumAuthorisationStatusType "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime           "json:\"statusUpdateDateTime\""
			UpdatedAtDateTime    *timeutil.DateTime          "json:\"updatedAtDateTime,omitempty\""
		}{
			AdditionalInformation: c.AdditionalInfo,
			ApprovalDueDate:       c.ApprovalDueAt,
			AuthorisedAtDateTime:  c.AuthorizedAt,
			CreationDateTime:      c.CreatedAt,
			ExpirationDateTime:    c.ExpiresAt,
			LoggedUser: &LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: c.UserIdentification,
					Rel:            string(c.UserRel),
				},
			},
			RecurringConfiguration: c.Configuration,
			RecurringConsentID:     c.URN(),
			Status:                 EnumAuthorisationStatusType(c.Status),
			StatusUpdateDateTime:   c.StatusUpdatedAt,
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
		resp.Data.DebtorAccount = &struct {
			AccountType EnumAccountTypeConsents "json:\"accountType\""
			Ispb        string                  "json:\"ispb\""
			Issuer      *string                 "json:\"issuer,omitempty\""
			Number      string                  "json:\"number\""
		}{
			Ispb:        s.config.ISPB(),
			Issuer:      &branch,
			Number:      c.DebtorAccount.Number,
			AccountType: EnumAccountTypeConsents(payment.ConvertAccountType(c.DebtorAccount.Type)),
		}
	}

	if c.Rejection != nil {
		resp.Data.Rejection = &struct {
			Reason       *ConsentRejectionReason                                "json:\"reason,omitempty\""
			RejectedAt   timeutil.DateTime                                      "json:\"rejectedAt\""
			RejectedBy   ResponseRecurringConsentPatchDataRejectionRejectedBy   "json:\"rejectedBy\""
			RejectedFrom ResponseRecurringConsentPatchDataRejectionRejectedFrom "json:\"rejectedFrom\""
		}{
			Reason: &ConsentRejectionReason{
				Code:   ConsentRejectionReasonCode(c.Rejection.Code),
				Detail: c.Rejection.Detail,
			},
			RejectedAt:   c.StatusUpdatedAt,
			RejectedBy:   ResponseRecurringConsentPatchDataRejectionRejectedBy(c.Rejection.By),
			RejectedFrom: ResponseRecurringConsentPatchDataRejectionRejectedFrom(c.Rejection.From),
		}
	}

	if c.Revocation != nil {
		resp.Data.Revocation = &struct {
			Reason *struct {
				Code   ResponseRecurringConsentPatchDataRevocationReasonCode "json:\"code\""
				Detail string                                                "json:\"detail\""
			} "json:\"reason,omitempty\""
			RevokedAt   timeutil.DateTime                                      "json:\"revokedAt\""
			RevokedBy   ResponseRecurringConsentPatchDataRevocationRevokedBy   "json:\"revokedBy\""
			RevokedFrom ResponseRecurringConsentPatchDataRevocationRevokedFrom "json:\"revokedFrom\""
		}{
			Reason: &struct {
				Code   ResponseRecurringConsentPatchDataRevocationReasonCode "json:\"code\""
				Detail string                                                "json:\"detail\""
			}{
				Code:   ResponseRecurringConsentPatchDataRevocationReasonCode(c.Revocation.Code),
				Detail: c.Revocation.Detail,
			},
			RevokedAt:   c.StatusUpdatedAt,
			RevokedBy:   ResponseRecurringConsentPatchDataRevocationRevokedBy(c.Revocation.By),
			RevokedFrom: ResponseRecurringConsentPatchDataRevocationRevokedFrom(c.Revocation.From),
		}
	}

	return AutomaticPaymentsPatchRecurringConsentsConsentID200JSONResponse{RecurringConsentsConsentIDPatchJSONResponse(resp)}, nil
}

func (s Server) AutomaticPaymentsPostPixRecurringPayments(ctx context.Context, req AutomaticPaymentsPostPixRecurringPaymentsRequestObject) (AutomaticPaymentsPostPixRecurringPaymentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	scopes := ctx.Value(api.CtxKeyScopes).(string)
	p := &autopayment.Payment{
		EndToEndID:                req.Body.Data.EndToEndID,
		Date:                      req.Body.Data.Date,
		Amount:                    req.Body.Data.Payment.Amount,
		Currency:                  req.Body.Data.Payment.Currency,
		CreditorAccountISBP:       req.Body.Data.CreditorAccount.Ispb,
		CreditorAccountIssuer:     req.Body.Data.CreditorAccount.Issuer,
		CreditorAccountNumber:     req.Body.Data.CreditorAccount.Number,
		CreditorAccountType:       payment.AccountType(req.Body.Data.CreditorAccount.AccountType),
		RemittanceInformation:     req.Body.Data.RemittanceInformation,
		CNPJInitiator:             req.Body.Data.CnpjInitiator,
		IBGETownCode:              req.Body.Data.IbgeTownCode,
		LocalInstrument:           payment.LocalInstrument(req.Body.Data.LocalInstrument),
		Proxy:                     req.Body.Data.Proxy,
		TransactionIdentification: req.Body.Data.TransactionIdentification,
		DocumentIdentification:    req.Body.Data.Document.Identification,
		DocumentRel:               consent.Relation(req.Body.Data.Document.Rel),
		Reference:                 req.Body.Data.PaymentReference,
		RiskSignals:               req.Body.Data.RiskSignals,
		Version:                   "v2",
		ClientID:                  clientID,
		OrgID:                     orgID,
	}

	if req.Body.Data.RecurringConsentID != nil {
		consentID := strings.TrimPrefix(*req.Body.Data.RecurringConsentID, autopayment.ConsentURNPrefix)
		p.ConsentID = uuid.MustParse(consentID)
	}

	if consentID, _ := autopayment.ConsentIDFromScopes(scopes); consentID != "" {
		p.ConsentID = uuid.MustParse(consentID)
	}
	if enrollmentID, _ := enrollment.IDFromScopes(scopes); enrollmentID != "" {
		id := uuid.MustParse(enrollmentID)
		p.EnrollmentID = &id
	}

	if req.Body.Data.AuthorisationFlow != nil {
		authFlow := payment.AuthorisationFlow(*req.Body.Data.AuthorisationFlow)
		p.AuthorisationFlow = &authFlow
	}

	if req.Body.Data.OriginalRecurringPaymentID != nil {
		originalID, err := uuid.Parse(*req.Body.Data.OriginalRecurringPaymentID)
		if err != nil {
			return nil, errorutil.New("invalid original recurring payment id")
		}
		p.OriginalID = &originalID
	}

	if err := s.service.Create(ctx, p); err != nil {
		return nil, err
	}

	consentID := autopayment.ConsentURN(p.ConsentID)
	resp := ResponseRecurringPaymentsIDPost{
		Data: ResponseRecurringPaymentsPostData{
			CnpjInitiator:    p.CNPJInitiator,
			CreationDateTime: p.CreatedAt,
			CreditorAccount: CreditorAccountPostPixPaymentsResponse{
				Ispb:        p.CreditorAccountISBP,
				Issuer:      p.CreditorAccountIssuer,
				Number:      p.CreditorAccountNumber,
				AccountType: EnumAccountTypePayments(payment.ConvertAccountType(p.DebtorAccount.Type)),
			},
			Date: p.Date,
			Document: struct {
				Identification string                                       `json:"identification"`
				Rel            ResponseRecurringPaymentsPostDataDocumentRel `json:"rel"`
			}{
				Identification: p.DocumentIdentification,
				Rel:            ResponseRecurringPaymentsPostDataDocumentRel(p.DocumentRel),
			},
			EndToEndID:      p.EndToEndID,
			LocalInstrument: ResponseRecurringPaymentsPostDataLocalInstrument(p.LocalInstrument),
			Payment: PaymentPix{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			PaymentReference:          p.Reference,
			Proxy:                     p.Proxy,
			RecurringConsentID:        &consentID,
			RecurringPaymentID:        p.ID.String(),
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/pix/recurring-payments/" + p.ID.String()),
	}

	if p.DebtorAccount != nil {
		branch := s.config.AccountBranch()
		resp.Data.DebtorAccount = &DebtorAccount{
			AccountType: EnumAccountTypeConsents(payment.ConvertAccountType(p.DebtorAccount.Type)),
			Issuer:      &branch,
			Ispb:        s.config.ISPB(),
			Number:      p.DebtorAccount.Number,
		}
	}

	if p.AuthorisationFlow != nil {
		authFlow := ResponseRecurringPaymentsPostDataAuthorisationFlow(*p.AuthorisationFlow)
		resp.Data.AuthorisationFlow = &authFlow
	}

	if p.OriginalID != nil {
		originalID := p.OriginalID.String()
		resp.Data.OriginalRecurringPaymentID = &originalID
	}

	if rejection := p.Rejection; rejection != nil {
		resp.Data.RejectionReason = &RejectionReason{
			Code:   EnumRejectionReasonCode(rejection.Code),
			Detail: rejection.Detail,
		}
	}

	if cancellation := p.Cancellation; cancellation != nil {
		resp.Data.Cancellation = &PixPaymentCancellation{
			CancelledAt: p.StatusUpdatedAt,
			CancelledBy: struct {
				Document struct {
					Identification string                                       "json:\"identification\""
					Rel            PixPaymentCancellationCancelledByDocumentRel "json:\"rel\""
				} "json:\"document\""
			}{
				Document: struct {
					Identification string                                       "json:\"identification\""
					Rel            PixPaymentCancellationCancelledByDocumentRel "json:\"rel\""
				}{
					Identification: cancellation.By,
					Rel:            "CPF",
				},
			},
			CancelledFrom: EnumPaymentCancellationFromType(cancellation.From),
			Reason:        EnumPaymentCancellationReasonType(cancellation.Reason),
		}
	}

	return AutomaticPaymentsPostPixRecurringPayments201JSONResponse{N201RecurringPaymentsIDPostJSONResponse(resp)}, nil
}

func (s Server) AutomaticPaymentsGetPixRecurringPaymentsPaymentID(ctx context.Context, req AutomaticPaymentsGetPixRecurringPaymentsPaymentIDRequestObject) (AutomaticPaymentsGetPixRecurringPaymentsPaymentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	p, err := s.service.Payment(ctx, req.RecurringPaymentID, orgID)
	if err != nil {
		return nil, err
	}

	consentID := autopayment.ConsentURN(p.ConsentID)
	resp := ResponseRecurringPaymentsIDRead{
		Data: ResponseRecurringPaymentsDataRead{
			CnpjInitiator:    p.CNPJInitiator,
			CreationDateTime: p.CreatedAt,
			CreditorAccount: &CreditorAccount{
				Ispb:        p.CreditorAccountISBP,
				Issuer:      p.CreditorAccountIssuer,
				Number:      p.CreditorAccountNumber,
				AccountType: EnumAccountTypePayments(payment.ConvertAccountType(p.DebtorAccount.Type)),
			},
			Date: p.Date,
			Document: struct {
				Identification string                                       `json:"identification"`
				Rel            ResponseRecurringPaymentsDataReadDocumentRel `json:"rel"`
			}{
				Identification: p.DocumentIdentification,
				Rel:            ResponseRecurringPaymentsDataReadDocumentRel(p.DocumentRel),
			},
			EndToEndID:      p.EndToEndID,
			LocalInstrument: ResponseRecurringPaymentsDataReadLocalInstrument(p.LocalInstrument),
			Payment: PaymentPix{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			PaymentReference:          p.Reference,
			Proxy:                     p.Proxy,
			RecurringConsentID:        &consentID,
			RecurringPaymentID:        p.ID.String(),
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/pix/recurring-payments/" + p.ID.String()),
	}

	if p.DebtorAccount != nil {
		branch := s.config.AccountBranch()
		resp.Data.DebtorAccount = &DebtorAccount{
			AccountType: EnumAccountTypeConsents(payment.ConvertAccountType(p.DebtorAccount.Type)),
			Issuer:      &branch,
			Ispb:        s.config.ISPB(),
			Number:      p.DebtorAccount.Number,
		}
	}

	if p.AuthorisationFlow != nil {
		authFlow := ResponseRecurringPaymentsDataReadAuthorisationFlow(*p.AuthorisationFlow)
		resp.Data.AuthorisationFlow = &authFlow
	}

	if p.OriginalID != nil {
		originalID := p.OriginalID.String()
		resp.Data.OriginalRecurringPaymentID = &originalID
	}

	if rejection := p.Rejection; rejection != nil {
		resp.Data.RejectionReason = &RejectionReason{
			Code:   EnumRejectionReasonCode(rejection.Code),
			Detail: rejection.Detail,
		}
	}

	if cancellation := p.Cancellation; cancellation != nil {
		resp.Data.Cancellation = &PixPaymentCancellation{
			CancelledAt: p.StatusUpdatedAt,
			CancelledBy: struct {
				Document struct {
					Identification string                                       "json:\"identification\""
					Rel            PixPaymentCancellationCancelledByDocumentRel "json:\"rel\""
				} "json:\"document\""
			}{
				Document: struct {
					Identification string                                       "json:\"identification\""
					Rel            PixPaymentCancellationCancelledByDocumentRel "json:\"rel\""
				}{
					Identification: cancellation.By,
					Rel:            "CPF",
				},
			},
			CancelledFrom: EnumPaymentCancellationFromType(cancellation.From),
			Reason:        EnumPaymentCancellationReasonType(cancellation.Reason),
		}
	}

	return AutomaticPaymentsGetPixRecurringPaymentsPaymentID200JSONResponse{N200RecurringPaymentsIDReadJSONResponse(resp)}, nil
}

func (s Server) AutomaticPaymentsGetPixRecurringPayments(ctx context.Context, req AutomaticPaymentsGetPixRecurringPaymentsRequestObject) (AutomaticPaymentsGetPixRecurringPaymentsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	filter := autopayment.Filter{ConsentID: req.Params.RecurringConsentID}
	payments, err := s.service.Payments(ctx, orgID, &filter)
	if err != nil {
		return nil, err
	}

	resp := ResponseRecurringPixPayment{
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/pix/recurring-payments" + filter.URLQuery()),
	}
	for _, p := range payments {
		consentID := autopayment.ConsentURN(p.ConsentID)
		data := struct {
			CreationDateTime timeutil.DateTime   "json:\"creationDateTime\""
			Date             timeutil.BrazilDate "json:\"date\""
			Document         struct {
				Identification string                              "json:\"identification\""
				Rel            ResponseRecurringPixDataDocumentRel "json:\"rel\""
			} "json:\"document\""
			EndToEndID                 EndToEndID                  "json:\"endToEndId\""
			OriginalRecurringPaymentID *OriginalRecurringPaymentID "json:\"originalRecurringPaymentId,omitempty\""
			Payment                    PaymentPix                  "json:\"payment\""
			PaymentReference           *string                     "json:\"paymentReference,omitempty\""
			RecurringConsentID         *string                     "json:\"recurringConsentId,omitempty\""
			RecurringPaymentID         string                      "json:\"recurringPaymentId\""
			RejectionReason            *RejectionReasonGet         "json:\"rejectionReason,omitempty\""
			RemittanceInformation      *string                     "json:\"remittanceInformation,omitempty\""
			Status                     EnumPaymentStatusType       "json:\"status\""
			StatusUpdateDateTime       timeutil.DateTime           "json:\"statusUpdateDateTime\""
			TransactionIdentification  *string                     "json:\"transactionIdentification,omitempty\""
		}{
			CreationDateTime: p.CreatedAt,
			Date:             p.Date,
			Document: struct {
				Identification string                              "json:\"identification\""
				Rel            ResponseRecurringPixDataDocumentRel "json:\"rel\""
			}{
				Identification: p.DocumentIdentification,
				Rel:            ResponseRecurringPixDataDocumentRel(p.DocumentRel),
			},
			EndToEndID: p.EndToEndID,
			Payment: PaymentPix{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			PaymentReference:          p.Reference,
			RecurringConsentID:        &consentID,
			RecurringPaymentID:        p.ID.String(),
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
		}

		if p.OriginalID != nil {
			originalID := p.OriginalID.String()
			data.OriginalRecurringPaymentID = &originalID
		}

		if rejection := p.Rejection; rejection != nil {
			data.RejectionReason = &RejectionReasonGet{
				Code:   EnumRejectionReasonCodeGet(rejection.Code),
				Detail: rejection.Detail,
			}
		}

		resp.Data = append(resp.Data, data)
	}

	return AutomaticPaymentsGetPixRecurringPayments200JSONResponse{N200RecurringPixPaymentReadJSONResponse(resp)}, nil
}

func (s Server) AutomaticPaymentsPatchPixRecurringPaymentsPaymentID(ctx context.Context, req AutomaticPaymentsPatchPixRecurringPaymentsPaymentIDRequestObject) (AutomaticPaymentsPatchPixRecurringPaymentsPaymentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	p, err := s.service.Cancel(ctx, req.RecurringPaymentID, orgID, consent.Document{
		Identification: req.Body.Data.Cancellation.CancelledBy.Document.Identification,
		Rel:            consent.Relation(req.Body.Data.Cancellation.CancelledBy.Document.Rel),
	})
	if err != nil {
		return nil, err
	}

	consentID := autopayment.ConsentURN(p.ConsentID)
	resp := ResponseRecurringPaymentsIDPatch{
		Data: ResponseRecurringPaymentsDataPatch{
			CnpjInitiator:    p.CNPJInitiator,
			CreationDateTime: p.CreatedAt,
			CreditorAccount: &CreditorAccount{
				Ispb:        p.CreditorAccountISBP,
				Issuer:      p.CreditorAccountIssuer,
				Number:      p.CreditorAccountNumber,
				AccountType: EnumAccountTypePayments(payment.ConvertAccountType(p.DebtorAccount.Type)),
			},
			Date: p.Date,
			Document: struct {
				Identification string                                        "json:\"identification\""
				Rel            ResponseRecurringPaymentsDataPatchDocumentRel "json:\"rel\""
			}{
				Identification: p.DocumentIdentification,
				Rel:            ResponseRecurringPaymentsDataPatchDocumentRel(p.DocumentRel),
			},
			EndToEndID:      p.EndToEndID,
			LocalInstrument: ResponseRecurringPaymentsDataPatchLocalInstrument(p.LocalInstrument),
			Payment: PaymentPix{
				Amount:   p.Amount,
				Currency: p.Currency,
			},
			PaymentReference:          p.Reference,
			Proxy:                     p.Proxy,
			RecurringConsentID:        &consentID,
			RecurringPaymentID:        p.ID.String(),
			RemittanceInformation:     p.RemittanceInformation,
			Status:                    EnumPaymentStatusType(p.Status),
			StatusUpdateDateTime:      p.StatusUpdatedAt,
			TransactionIdentification: p.TransactionIdentification,
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/pix/recurring-payments/" + p.ID.String()),
	}

	if p.DebtorAccount != nil {
		branch := s.config.AccountBranch()
		resp.Data.DebtorAccount = &DebtorAccount{
			AccountType: EnumAccountTypeConsents(payment.ConvertAccountType(p.DebtorAccount.Type)),
			Issuer:      &branch,
			Ispb:        s.config.ISPB(),
			Number:      p.DebtorAccount.Number,
		}
	}

	if p.AuthorisationFlow != nil {
		authFlow := ResponseRecurringPaymentsDataPatchAuthorisationFlow(*p.AuthorisationFlow)
		resp.Data.AuthorisationFlow = &authFlow
	}

	if p.OriginalID != nil {
		originalID := p.OriginalID.String()
		resp.Data.OriginalRecurringPaymentID = &originalID
	}

	if rejection := p.Rejection; rejection != nil {
		resp.Data.RejectionReason = &RejectionReason{
			Code:   EnumRejectionReasonCode(rejection.Code),
			Detail: rejection.Detail,
		}
	}

	if cancellation := p.Cancellation; cancellation != nil {
		resp.Data.Cancellation = &PixPaymentCancellation{
			CancelledAt: p.StatusUpdatedAt,
			CancelledBy: struct {
				Document struct {
					Identification string                                       "json:\"identification\""
					Rel            PixPaymentCancellationCancelledByDocumentRel "json:\"rel\""
				} "json:\"document\""
			}{
				Document: struct {
					Identification string                                       "json:\"identification\""
					Rel            PixPaymentCancellationCancelledByDocumentRel "json:\"rel\""
				}{
					Identification: cancellation.By,
					Rel:            "CPF",
				},
			},
			CancelledFrom: EnumPaymentCancellationFromType(cancellation.From),
			Reason:        EnumPaymentCancellationReasonType(cancellation.Reason),
		}
	}

	return AutomaticPaymentsPatchPixRecurringPaymentsPaymentID200JSONResponse{N200RecurringPaymentsIDPatchJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, autopayment.ErrInvalidEndToEndID) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrInvalidPayment) {
		api.WriteError(w, r, api.NewError("DETALHE_PAGAMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrPaymentDoesNotMatchConsent) {
		api.WriteError(w, r, api.NewError("PAGAMENTO_DIVERGENTE_CONSENTIMENTO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrInvalidDate) {
		api.WriteError(w, r, api.NewError("DATA_PAGAMENTO_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrMissingValue) {
		api.WriteError(w, r, api.NewError("PARAMETRO_NAO_INFORMADO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrCancelNotAllowed) {
		api.WriteError(w, r, api.NewError("PAGAMENTO_NAO_PERMITE_CANCELAMENTO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrInvalidConsentStatus) {
		api.WriteError(w, r, api.NewError("CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrInvalidData) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrInvalidEdition) {
		api.WriteError(w, r, api.NewError("DETALHE_EDICAO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrFieldNotAllowed) {
		api.WriteError(w, r, api.NewError("CAMPO_NAO_PERMITIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrConsentPartiallyAccepted) {
		api.WriteError(w, r, api.NewError("CONSENTIMENTO_PENDENTE_AUTORIZACAO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.As(err, &errorutil.Error{}) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}
