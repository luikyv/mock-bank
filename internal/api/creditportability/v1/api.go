//go:generate oapi-codegen -config=./config.yml -package=v1 -o=./api_gen.go ./swagger.yml
package v1

import (
	"context"
	"crypto"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/creditportability"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
)

var _ StrictServerInterface = Server{}

type BankConfig interface {
	Host() string
	Brand() string
	CNPJ() string
	ISPB() string
}

type Server struct {
	config             BankConfig
	baseURL            string
	service            creditportability.Service
	idempotencyService idempotency.Service
	jwtService         jwtutil.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	config BankConfig,
	service creditportability.Service,
	idempotencyService idempotency.Service,
	jwtService jwtutil.Service,
	op *provider.Provider,
	orgID string,
	keystoreHost string,
	signer crypto.Signer,
) *Server {
	return &Server{
		config:             config,
		service:            service,
		idempotencyService: idempotencyService,
		jwtService:         jwtService,
		op:                 op,
		orgID:              orgID,
		keystoreHost:       keystoreHost,
		signer:             signer,
	}
}

func (s Server) Handler() (http.Handler, string) {
	mux := http.NewServeMux()

	jwtMiddleware := middleware.JWT(s.baseURL, s.orgID, s.keystoreHost, s.signer, s.jwtService)
	idempotencyMiddleware := middleware.Idempotency(s.idempotencyService)
	clientCredentialsAuthMiddleware := middleware.Auth(s.op, goidc.GrantClientCredentials, creditportability.Scope)
	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID, creditportability.Scope)
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

	handler = http.HandlerFunc(wrapper.CreditPortabilityPostPortabilities)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	mux.Handle("POST /portabilities", handler)

	handler = http.HandlerFunc(wrapper.CreditPortabilityGetCreditOperationsContratIDPortabilityEligibility)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	mux.Handle("GET /credit-operations/{contractId}/portability-eligibility", handler)

	handler = http.HandlerFunc(wrapper.CreditPortabilityGetPortabilitiesByPortabilityID)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("GET /portabilities/{portabilityId}", handler)

	handler = http.HandlerFunc(wrapper.CreditPortabilityGetAccountData)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("GET /portabilities/{portabilityId}/account-data", handler)

	handler = http.HandlerFunc(wrapper.CreditPortabilityPatchPortabilitiesPortabilityIDCancel)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("PATCH /portabilities/{portabilityId}/cancel", handler)

	handler = http.HandlerFunc(wrapper.CreditPortabilityPostPortabilitiesPortabilityIDPayment)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	mux.Handle("POST /portabilities/{portabilityId}/payment", handler)

	return http.StripPrefix("/open-banking/credit-portability/v1", handler), swaggerVersion
}

func (s Server) CreditPortabilityGetCreditOperationsContratIDPortabilityEligibility(ctx context.Context, request CreditPortabilityGetCreditOperationsContratIDPortabilityEligibilityRequestObject) (CreditPortabilityGetCreditOperationsContratIDPortabilityEligibilityResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	eligibility, err := s.service.Eligibility(ctx, request.ContractID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponsePortabilityEligibility{
		Data: struct {
			ContractID  string "json:\"contractId\""
			Portability struct {
				Channel     *ResponsePortabilityEligibilityDataPortabilityChannel "json:\"channel,omitempty\""
				CompanyCnpj *string                                               "json:\"companyCnpj,omitempty\""
				CompanyName *string                                               "json:\"companyName,omitempty\""
				Ineligible  *struct {
					ReasonType               ResponsePortabilityEligibilityDataPortabilityIneligibleReasonType "json:\"reasonType\""
					ReasonTypeAdditionalInfo *string                                                           "json:\"reasonTypeAdditionalInfo,omitempty\""
				} "json:\"ineligible,omitempty\""
				IsEligible           bool                                                 "json:\"isEligible\""
				Status               *ResponsePortabilityEligibilityDataPortabilityStatus "json:\"status,omitempty\""
				StatusUpdateDateTime *string                                              "json:\"statusUpdateDateTime,omitempty\""
			} "json:\"portability\""
		}{
			ContractID: eligibility.ContractID,
			Portability: struct {
				Channel     *ResponsePortabilityEligibilityDataPortabilityChannel "json:\"channel,omitempty\""
				CompanyCnpj *string                                               "json:\"companyCnpj,omitempty\""
				CompanyName *string                                               "json:\"companyName,omitempty\""
				Ineligible  *struct {
					ReasonType               ResponsePortabilityEligibilityDataPortabilityIneligibleReasonType "json:\"reasonType\""
					ReasonTypeAdditionalInfo *string                                                           "json:\"reasonTypeAdditionalInfo,omitempty\""
				} "json:\"ineligible,omitempty\""
				IsEligible           bool                                                 "json:\"isEligible\""
				Status               *ResponsePortabilityEligibilityDataPortabilityStatus "json:\"status,omitempty\""
				StatusUpdateDateTime *string                                              "json:\"statusUpdateDateTime,omitempty\""
			}{
				IsEligible:  eligibility.IsEligible,
				CompanyName: eligibility.CompanyName,
			},
		},
		Meta:  api.NewMeta(),
		Links: api.NewLinks(s.baseURL + "/credit-operations/" + request.ContractID + "/portability-eligibility"),
	}

	if eligibility.Channel != nil {
		resp.Data.Portability.Channel = pointerOf(ResponsePortabilityEligibilityDataPortabilityChannel(*eligibility.Channel))
	}

	if eligibility.IneligibilityReason != nil {
		resp.Data.Portability.Ineligible = pointerOf(struct {
			ReasonType               ResponsePortabilityEligibilityDataPortabilityIneligibleReasonType "json:\"reasonType\""
			ReasonTypeAdditionalInfo *string                                                           "json:\"reasonTypeAdditionalInfo,omitempty\""
		}{
			ReasonType:               ResponsePortabilityEligibilityDataPortabilityIneligibleReasonType(*eligibility.IneligibilityReason),
			ReasonTypeAdditionalInfo: eligibility.IneligibilityReasonAdditionalInfo,
		})
	}

	if eligibility.Status != nil {
		resp.Data.Portability.Status = pointerOf(ResponsePortabilityEligibilityDataPortabilityStatus(*eligibility.Status))
	}

	return CreditPortabilityGetCreditOperationsContratIDPortabilityEligibility200JSONResponse{OKResponsePortabilityEligibilityJSONResponse(resp)}, nil
}

func (s Server) CreditPortabilityPostPortabilities(ctx context.Context, request CreditPortabilityPostPortabilitiesRequestObject) (CreditPortabilityPostPortabilitiesResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityGetPortabilitiesByPortabilityID(ctx context.Context, request CreditPortabilityGetPortabilitiesByPortabilityIDRequestObject) (CreditPortabilityGetPortabilitiesByPortabilityIDResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityGetAccountData(ctx context.Context, req CreditPortabilityGetAccountDataRequestObject) (CreditPortabilityGetAccountDataResponseObject, error) {
	_, err := s.service.AccountData(ctx, req.PortabilityID)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountData{
		Data: struct {
			StrCode struct {
				AccountNumber     *float32 "json:\"accountNumber,omitempty\""
				BranchCode        float32  "json:\"branchCode\""
				CompanyCnpj       *string  "json:\"companyCnpj,omitempty\""
				HasFinancialAgent bool     "json:\"hasFinancialAgent\""
				Ispb              string   "json:\"ispb\""
				Name              *string  "json:\"name,omitempty\""
			} "json:\"strCode\""
		}{
			StrCode: struct {
				AccountNumber     *float32 "json:\"accountNumber,omitempty\""
				BranchCode        float32  "json:\"branchCode\""
				CompanyCnpj       *string  "json:\"companyCnpj,omitempty\""
				HasFinancialAgent bool     "json:\"hasFinancialAgent\""
				Ispb              string   "json:\"ispb\""
				Name              *string  "json:\"name,omitempty\""
			}{
				// BranchCode:  pointerOf(float32(s.config.BranchCode())),
				CompanyCnpj: pointerOf(s.config.CNPJ()),
				Ispb:        s.config.ISPB(),
				Name:        pointerOf(s.config.Brand()),
			},
		},
	}
	return CreditPortabilityGetAccountData200JSONResponse{OKResponseAccountDataJSONResponse(resp)}, nil
}

func (s Server) CreditPortabilityPatchPortabilitiesPortabilityIDCancel(ctx context.Context, request CreditPortabilityPatchPortabilitiesPortabilityIDCancelRequestObject) (CreditPortabilityPatchPortabilitiesPortabilityIDCancelResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityPostPortabilitiesPortabilityIDPayment(ctx context.Context, request CreditPortabilityPostPortabilitiesPortabilityIDPaymentRequestObject) (CreditPortabilityPostPortabilitiesPortabilityIDPaymentResponseObject, error) {
	return nil, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	api.WriteError(w, r, err)
}

func pointerOf[T any](v T) *T {
	return &v
}
