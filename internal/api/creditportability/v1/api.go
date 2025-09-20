//go:generate oapi-codegen -config=./config.yml -package=v1 -o=./api_gen.go ./swagger.yml
package v1

import (
	"context"
	"crypto"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/creditportability"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
	"github.com/luikyv/mock-bank/internal/timeutil"
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
	consentService     consent.Service
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
	consentService consent.Service,
	idempotencyService idempotency.Service,
	jwtService jwtutil.Service,
	op *provider.Provider,
	orgID string,
	keystoreHost string,
	signer crypto.Signer,
) *Server {
	return &Server{
		config:             config,
		baseURL:            config.Host() + "/open-banking/credit-portability/v1",
		service:            service,
		consentService:     consentService,
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
	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID, consent.ScopeID)
	swaggerMiddleware, swaggerVersion := middleware.Swagger(GetSwagger, func(err error) api.Error {
		var schemaErr *openapi3.SchemaError
		if errors.As(err, &schemaErr) && schemaErr.SchemaField == "required" {
			path := schemaErr.JSONPointer()
			if path[len(path)-1] == "digitalSignatureProof" {
				return api.NewError("SEM_EVIDENCIA_ASSINATURA", http.StatusUnprocessableEntity, err.Error())
			}
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
	handler = middleware.PermissionWithOptions(s.consentService, &middleware.Options{ErrorPagination: true}, consent.PermissionLoansRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	mux.Handle("POST /portabilities", handler)

	handler = http.HandlerFunc(wrapper.CreditPortabilityGetCreditOperationsContratIDPortabilityEligibility)
	handler = jwtMiddleware(handler)
	handler = middleware.PermissionWithOptions(s.consentService, &middleware.Options{ErrorPagination: true}, consent.PermissionLoansRead)(handler)
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

	handler = middleware.FAPIID()(mux)
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
				StatusUpdateDateTime *timeutil.DateTime                                   "json:\"statusUpdateDateTime,omitempty\""
			} "json:\"portability\""
		}{
			ContractID: eligibility.ContractID.String(),
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
				StatusUpdateDateTime *timeutil.DateTime                                   "json:\"statusUpdateDateTime,omitempty\""
			}{
				IsEligible:           eligibility.IsEligible,
				CompanyName:          eligibility.CompanyName,
				CompanyCnpj:          eligibility.CompanyCNPJ,
				StatusUpdateDateTime: eligibility.StatusUpdatedAt,
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

func (s Server) CreditPortabilityPostPortabilities(ctx context.Context, req CreditPortabilityPostPortabilitiesRequestObject) (CreditPortabilityPostPortabilitiesResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	clientID := ctx.Value(api.CtxKeyClientID).(string)

	portability := &creditportability.Portability{
		ConsentID:                                   uuid.MustParse(consentID),
		ContractID:                                  uuid.MustParse(req.Body.Data.ContractIdentification.ContractID),
		ContractNumber:                              req.Body.Data.ContractIdentification.ContractNumber,
		ContractIPOCCode:                            req.Body.Data.ContractIdentification.IpocCode,
		CreditorInstitutionName:                     req.Body.Data.Institution.Creditor.CompanyName,
		CreditorInstitutionCNPJ:                     req.Body.Data.Institution.Creditor.CompanyCnpj,
		ProposingInstitutionName:                    req.Body.Data.Institution.Proposing.CompanyName,
		ProposingInstitutionCNPJ:                    req.Body.Data.Institution.Proposing.CompanyCnpj,
		ProposedInstalmentCurrency:                  req.Body.Data.ProposedContract.InstallmentAmount.Currency,
		ProposedInstalmentAmount:                    req.Body.Data.ProposedContract.InstallmentAmount.Amount,
		ProposedTotalInstalments:                    int(req.Body.Data.ProposedContract.TotalNumberOfInstallments),
		ProposedInstalmentPeriodicity:               creditop.Periodicity(req.Body.Data.ProposedContract.InstalmentPeriodicity),
		DigitalSignatureProofDocumentID:             req.Body.Data.ProposedContract.DigitalSignatureProof.DocumentID,
		DigitalSignatureProofSignedAt:               req.Body.Data.ProposedContract.DigitalSignatureProof.SignatureDateTime,
		ProposedAmortizationSchedule:                creditop.AmortizationSchedule(req.Body.Data.ProposedContract.AmortizationScheduled),
		ProposedAmortizationScheduledAdditionalInfo: req.Body.Data.ProposedContract.AmortizationScheduledAdditionalInfo,
		ProposedDueDate:                             req.Body.Data.ProposedContract.DueDate,
		ProposedCET:                                 req.Body.Data.ProposedContract.CET,
		ProposedAmount:                              req.Body.Data.ProposedContract.ContractAmount.Amount,
		ProposedCurrency:                            req.Body.Data.ProposedContract.ContractAmount.Currency,
		ClientID:                                    clientID,
		OrgID:                                       orgID,
		Status:                                      creditportability.StatusReceived,
		StatusUpdatedAt:                             timeutil.DateTimeNow(),
	}

	for _, contact := range req.Body.Data.CustomerContact {
		portability.CustomerContacts = append(portability.CustomerContacts, creditportability.Contact{
			Type:  creditportability.ContactType(contact.Type),
			Value: contact.Value,
		})
	}

	for _, interestRate := range req.Body.Data.ProposedContract.InterestRates {
		data := creditop.InterestRate{
			Type:                      creditop.InterestRateType(interestRate.InterestRateType),
			TaxType:                   creditop.TaxType(interestRate.TaxType),
			TaxPeriodicity:            creditop.TaxPeriodicity(interestRate.TaxPeriodicity),
			Calculation:               creditop.Calculation(interestRate.Calculation),
			RateIndexerType:           creditop.RateIndexerType(interestRate.ReferentialRateIndexerType),
			RateIndexerAdditionalInfo: interestRate.ReferentialRateIndexerAdditionalInfo,
			FixedRate:                 &interestRate.PreFixedRate,
			PostFixedRate:             &interestRate.PostFixedRate,
			AdditionalInfo:            interestRate.AdditionalInfo,
		}
		if interestRate.ReferentialRateIndexerSubType != nil {
			data.RateIndexerSubType = pointerOf(creditop.RateIndexerSubType(*interestRate.ReferentialRateIndexerSubType))
		}
		portability.ProposedInterestRates = append(portability.ProposedInterestRates, data)
	}

	for _, fee := range req.Body.Data.ProposedContract.ContractedFees {
		data := creditop.Fee{
			Name:              fee.FeeName,
			Code:              fee.FeeCode,
			ChargeType:        creditop.ChargeType(fee.FeeChargeType),
			ChargeCalculation: creditop.ChargeCalculation(fee.FeeCharge),
			Rate:              fee.FeeRate,
		}
		if fee.FeeAmount != nil {
			data.Amount = &fee.FeeAmount.Amount
		}
		portability.ProposedFees = append(portability.ProposedFees, data)
	}

	// Map proposed finance charges
	for _, financeCharge := range req.Body.Data.ProposedContract.ContractedFinanceCharges {
		portability.ProposedFinanceCharges = append(portability.ProposedFinanceCharges, creditop.FinanceCharge{
			Type:           creditop.FinanceChargeType(financeCharge.ChargeType),
			AdditionalInfo: financeCharge.ChargeAdditionalInfo,
			Rate:           &financeCharge.ChargeRate,
		})
	}

	if req.Body.Data.Institution.Proposing.Contact != nil {
		proposingContacts := make([]creditportability.Contact, len(*req.Body.Data.Institution.Proposing.Contact))
		for i, c := range *req.Body.Data.Institution.Proposing.Contact {
			proposingContact := creditportability.Contact{}
			if c.Type != nil {
				proposingContact.Type = creditportability.ContactType(*c.Type)
			}
			if c.Value != nil {
				proposingContact.Value = *c.Value
			}
			proposingContacts[i] = proposingContact
		}
		portability.ProposingInstitutionContacts = &proposingContacts
	}

	err := s.service.Create(ctx, portability)
	if err != nil {
		return nil, err
	}

	resp := POSTResponseCreditPortability{
		Data: struct {
			CreationDateTime string                                   "json:\"creationDateTime\""
			PortabilityID    string                                   "json:\"portabilityId\""
			Status           *POSTResponseCreditPortabilityDataStatus "json:\"status,omitempty\""
		}{
			PortabilityID:    portability.ID.String(),
			Status:           pointerOf(POSTResponseCreditPortabilityDataStatus(portability.Status)),
			CreationDateTime: portability.CreatedAt.String(),
		},
		Meta: api.NewMeta(),
	}

	return CreditPortabilityPostPortabilities202JSONResponse{POSTResponseCreditPortabilityJSONResponse(resp)}, nil
}

func (s Server) CreditPortabilityGetPortabilitiesByPortabilityID(ctx context.Context, req CreditPortabilityGetPortabilitiesByPortabilityIDRequestObject) (CreditPortabilityGetPortabilitiesByPortabilityIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)

	portability, err := s.service.Portability(ctx, creditportability.Query{ID: string(req.PortabilityID)}, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponsePortabilitiesByPortabilityID{
		Data: struct {
			ContractIdentification struct {
				ContractID     string "json:\"contractId\""
				ContractNumber string "json:\"contractNumber\""
				IpocCode       string "json:\"ipocCode\""
			} "json:\"contractIdentification\""
			CreationDateTime string "json:\"creationDateTime\""
			CustomerContact  []struct {
				Type  ResponsePortabilitiesByPortabilityIDDataCustomerContactType "json:\"type\""
				Value string                                                      "json:\"value\""
			} "json:\"customerContact\""
			Institution struct {
				Creditor struct {
					CompanyCnpj string "json:\"companyCnpj\""
					CompanyName string "json:\"companyName\""
				} "json:\"creditor\""
				Proposing struct {
					CompanyCnpj string "json:\"companyCnpj\""
					CompanyName string "json:\"companyName\""
					Contact     *[]struct {
						Type  *ResponsePortabilitiesByPortabilityIDDataInstitutionProposingContactType "json:\"type,omitempty\""
						Value *string                                                                  "json:\"value,omitempty\""
					} "json:\"contact,omitempty\""
				} "json:\"proposing\""
			} "json:\"institution\""
			LoanSettlementInstruction *struct {
				SettlementAmount struct {
					Amount   string "json:\"amount\""
					Currency string "json:\"currency\""
				} "json:\"settlementAmount\""
				SettlementDateTime timeutil.DateTime "json:\"settlementDateTime\""
				TransactionID      string            "json:\"transactionId\""
			} "json:\"loanSettlementInstruction,omitempty\""
			PortabilityID    string "json:\"portabilityId\""
			ProposedContract struct {
				CET                                 string                                                                        "json:\"CET\""
				AmortizationScheduled               ResponsePortabilitiesByPortabilityIDDataProposedContractAmortizationScheduled "json:\"amortizationScheduled\""
				AmortizationScheduledAdditionalInfo *string                                                                       "json:\"amortizationScheduledAdditionalInfo,omitempty\""
				ContractAmount                      struct {
					Amount   string "json:\"amount\""
					Currency string "json:\"currency\""
				} "json:\"contractAmount\""
				ContractedFees []struct {
					FeeAmount *struct {
						Amount   string "json:\"amount\""
						Currency string "json:\"currency\""
					} "json:\"feeAmount,omitempty\""
					FeeCharge     ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeCharge     "json:\"feeCharge\""
					FeeChargeType ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeChargeType "json:\"feeChargeType\""
					FeeCode       string                                                                              "json:\"feeCode\""
					FeeName       string                                                                              "json:\"feeName\""
					FeeRate       *string                                                                             "json:\"feeRate,omitempty\""
				} "json:\"contractedFees\""
				ContractedFinanceCharges []struct {
					ChargeAdditionalInfo *string                                                                                    "json:\"chargeAdditionalInfo,omitempty\""
					ChargeRate           *string                                                                                    "json:\"chargeRate,omitempty\""
					ChargeType           ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFinanceChargesChargeType "json:\"chargeType\""
				} "json:\"contractedFinanceCharges\""
				DigitalSignatureProof struct {
					DocumentID        string "json:\"documentId\""
					SignatureDateTime string "json:\"signatureDateTime\""
				} "json:\"digitalSignatureProof\""
				DueDate           string "json:\"dueDate\""
				InstallmentAmount *struct {
					Amount   string "json:\"amount\""
					Currency string "json:\"currency\""
				} "json:\"installmentAmount,omitempty\""
				InstalmentPeriodicity     ResponsePortabilitiesByPortabilityIDDataProposedContractInstalmentPeriodicity "json:\"instalmentPeriodicity\""
				InterestRates             []LoansContractInterestRate                                                   "json:\"interestRates\""
				TotalNumberOfInstallments float32                                                                       "json:\"totalNumberOfInstallments\""
			} "json:\"proposedContract\""
			Rejection *struct {
				Reason struct {
					Type               ResponsePortabilitiesByPortabilityIDDataRejectionReasonType "json:\"type\""
					TypeAdditionalInfo *string                                                     "json:\"typeAdditionalInfo,omitempty\""
				} "json:\"reason\""
				RejectedBy ResponsePortabilitiesByPortabilityIDDataRejectionRejectedBy "json:\"rejectedBy\""
			} "json:\"rejection,omitempty\""
			Status       ResponsePortabilitiesByPortabilityIDDataStatus "json:\"status\""
			StatusReason *struct {
				DigitalSignatureProof *struct {
					DocumentID        string "json:\"documentId\""
					SignatureDateTime string "json:\"signatureDateTime\""
				} "json:\"digitalSignatureProof,omitempty\""
				ReasonType               *ResponsePortabilitiesByPortabilityIDDataStatusReasonReasonType "json:\"reasonType,omitempty\""
				ReasonTypeAdditionalInfo *string                                                         "json:\"reasonTypeAdditionalInfo,omitempty\""
			} "json:\"statusReason,omitempty\""
			StatusUpdateDateTime timeutil.DateTime "json:\"statusUpdateDateTime\""
		}{
			ContractIdentification: struct {
				ContractID     string "json:\"contractId\""
				ContractNumber string "json:\"contractNumber\""
				IpocCode       string "json:\"ipocCode\""
			}{
				ContractID:     portability.ContractID.String(),
				ContractNumber: portability.ContractNumber,
				IpocCode:       portability.ContractIPOCCode,
			},
			CreationDateTime: portability.CreatedAt.String(),
			Institution: struct {
				Creditor struct {
					CompanyCnpj string "json:\"companyCnpj\""
					CompanyName string "json:\"companyName\""
				} "json:\"creditor\""
				Proposing struct {
					CompanyCnpj string "json:\"companyCnpj\""
					CompanyName string "json:\"companyName\""
					Contact     *[]struct {
						Type  *ResponsePortabilitiesByPortabilityIDDataInstitutionProposingContactType "json:\"type,omitempty\""
						Value *string                                                                  "json:\"value,omitempty\""
					} "json:\"contact,omitempty\""
				} "json:\"proposing\""
			}{
				Creditor: struct {
					CompanyCnpj string "json:\"companyCnpj\""
					CompanyName string "json:\"companyName\""
				}{
					CompanyCnpj: portability.CreditorInstitutionCNPJ,
					CompanyName: portability.CreditorInstitutionName,
				},
				Proposing: struct {
					CompanyCnpj string "json:\"companyCnpj\""
					CompanyName string "json:\"companyName\""
					Contact     *[]struct {
						Type  *ResponsePortabilitiesByPortabilityIDDataInstitutionProposingContactType "json:\"type,omitempty\""
						Value *string                                                                  "json:\"value,omitempty\""
					} "json:\"contact,omitempty\""
				}{
					CompanyCnpj: portability.ProposingInstitutionCNPJ,
					CompanyName: portability.ProposingInstitutionName,
				},
			},
			PortabilityID: portability.ID.String(),
			ProposedContract: struct {
				CET                                 string                                                                        "json:\"CET\""
				AmortizationScheduled               ResponsePortabilitiesByPortabilityIDDataProposedContractAmortizationScheduled "json:\"amortizationScheduled\""
				AmortizationScheduledAdditionalInfo *string                                                                       "json:\"amortizationScheduledAdditionalInfo,omitempty\""
				ContractAmount                      struct {
					Amount   string "json:\"amount\""
					Currency string "json:\"currency\""
				} "json:\"contractAmount\""
				ContractedFees []struct {
					FeeAmount *struct {
						Amount   string "json:\"amount\""
						Currency string "json:\"currency\""
					} "json:\"feeAmount,omitempty\""
					FeeCharge     ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeCharge     "json:\"feeCharge\""
					FeeChargeType ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeChargeType "json:\"feeChargeType\""
					FeeCode       string                                                                              "json:\"feeCode\""
					FeeName       string                                                                              "json:\"feeName\""
					FeeRate       *string                                                                             "json:\"feeRate,omitempty\""
				} "json:\"contractedFees\""
				ContractedFinanceCharges []struct {
					ChargeAdditionalInfo *string                                                                                    "json:\"chargeAdditionalInfo,omitempty\""
					ChargeRate           *string                                                                                    "json:\"chargeRate,omitempty\""
					ChargeType           ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFinanceChargesChargeType "json:\"chargeType\""
				} "json:\"contractedFinanceCharges\""
				DigitalSignatureProof struct {
					DocumentID        string "json:\"documentId\""
					SignatureDateTime string "json:\"signatureDateTime\""
				} "json:\"digitalSignatureProof\""
				DueDate           string "json:\"dueDate\""
				InstallmentAmount *struct {
					Amount   string "json:\"amount\""
					Currency string "json:\"currency\""
				} "json:\"installmentAmount,omitempty\""
				InstalmentPeriodicity     ResponsePortabilitiesByPortabilityIDDataProposedContractInstalmentPeriodicity "json:\"instalmentPeriodicity\""
				InterestRates             []LoansContractInterestRate                                                   "json:\"interestRates\""
				TotalNumberOfInstallments float32                                                                       "json:\"totalNumberOfInstallments\""
			}{
				CET:                                 portability.ProposedCET,
				AmortizationScheduled:               ResponsePortabilitiesByPortabilityIDDataProposedContractAmortizationScheduled(portability.ProposedAmortizationSchedule),
				AmortizationScheduledAdditionalInfo: portability.ProposedAmortizationScheduledAdditionalInfo,
				ContractAmount: struct {
					Amount   string "json:\"amount\""
					Currency string "json:\"currency\""
				}{
					Amount:   portability.ProposedAmount,
					Currency: portability.ProposedCurrency,
				},
				DigitalSignatureProof: struct {
					DocumentID        string "json:\"documentId\""
					SignatureDateTime string "json:\"signatureDateTime\""
				}{
					DocumentID:        portability.DigitalSignatureProofDocumentID,
					SignatureDateTime: portability.DigitalSignatureProofSignedAt,
				},
				DueDate:                   portability.ProposedDueDate,
				InstalmentPeriodicity:     ResponsePortabilitiesByPortabilityIDDataProposedContractInstalmentPeriodicity(portability.ProposedInstalmentPeriodicity),
				TotalNumberOfInstallments: float32(portability.ProposedTotalInstalments),
			},
			Status:               ResponsePortabilitiesByPortabilityIDDataStatus(portability.Status),
			StatusUpdateDateTime: portability.StatusUpdatedAt,
		},
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/portabilities/" + string(req.PortabilityID)),
	}

	for _, contact := range portability.CustomerContacts {
		resp.Data.CustomerContact = append(resp.Data.CustomerContact, struct {
			Type  ResponsePortabilitiesByPortabilityIDDataCustomerContactType "json:\"type\""
			Value string                                                      "json:\"value\""
		}{
			Type:  ResponsePortabilitiesByPortabilityIDDataCustomerContactType(contact.Type),
			Value: contact.Value,
		})
	}

	if portability.ProposingInstitutionContacts != nil {
		proposingContacts := make([]struct {
			Type  *ResponsePortabilitiesByPortabilityIDDataInstitutionProposingContactType "json:\"type,omitempty\""
			Value *string                                                                  "json:\"value,omitempty\""
		}, len(*portability.ProposingInstitutionContacts))
		for i, contact := range *portability.ProposingInstitutionContacts {
			proposingContacts[i] = struct {
				Type  *ResponsePortabilitiesByPortabilityIDDataInstitutionProposingContactType "json:\"type,omitempty\""
				Value *string                                                                  "json:\"value,omitempty\""
			}{
				Type:  pointerOf(ResponsePortabilitiesByPortabilityIDDataInstitutionProposingContactType(contact.Type)),
				Value: pointerOf(contact.Value),
			}
		}
		resp.Data.Institution.Proposing.Contact = &proposingContacts
	}

	if portability.LoanSettlementInstruction != nil {
		resp.Data.LoanSettlementInstruction = &struct {
			SettlementAmount struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			} "json:\"settlementAmount\""
			SettlementDateTime timeutil.DateTime "json:\"settlementDateTime\""
			TransactionID      string            "json:\"transactionId\""
		}{
			SettlementAmount: struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			}{
				Amount:   portability.LoanSettlementInstruction.Amount,
				Currency: portability.LoanSettlementInstruction.Currency,
			},
			SettlementDateTime: portability.LoanSettlementInstruction.DateTime,
			TransactionID:      portability.LoanSettlementInstruction.TransactionID,
		}
	}

	for _, fee := range portability.ProposedFees {
		data := struct {
			FeeAmount *struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			} "json:\"feeAmount,omitempty\""
			FeeCharge     ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeCharge     "json:\"feeCharge\""
			FeeChargeType ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeChargeType "json:\"feeChargeType\""
			FeeCode       string                                                                              "json:\"feeCode\""
			FeeName       string                                                                              "json:\"feeName\""
			FeeRate       *string                                                                             "json:\"feeRate,omitempty\""
		}{
			FeeCharge:     ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeCharge(fee.ChargeCalculation),
			FeeChargeType: ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFeesFeeChargeType(fee.ChargeType),
			FeeCode:       fee.Code,
			FeeName:       fee.Name,
			FeeRate:       fee.Rate,
		}
		if fee.Amount != nil {
			data.FeeAmount = &struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			}{
				Amount:   *fee.Amount,
				Currency: "BRL",
			}
		}
		resp.Data.ProposedContract.ContractedFees = append(resp.Data.ProposedContract.ContractedFees, data)
	}

	for _, financeCharge := range portability.ProposedFinanceCharges {
		data := struct {
			ChargeAdditionalInfo *string                                                                                    "json:\"chargeAdditionalInfo,omitempty\""
			ChargeRate           *string                                                                                    "json:\"chargeRate,omitempty\""
			ChargeType           ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFinanceChargesChargeType "json:\"chargeType\""
		}{
			ChargeAdditionalInfo: financeCharge.AdditionalInfo,
			ChargeRate:           financeCharge.Rate,
			ChargeType:           ResponsePortabilitiesByPortabilityIDDataProposedContractContractedFinanceChargesChargeType(financeCharge.Type),
		}
		resp.Data.ProposedContract.ContractedFinanceCharges = append(resp.Data.ProposedContract.ContractedFinanceCharges, data)
	}

	for _, interestRate := range portability.ProposedInterestRates {
		data := LoansContractInterestRate{
			InterestRateType:                     LoansContractInterestRateInterestRateType(interestRate.Type),
			TaxType:                              LoansContractInterestRateTaxType(interestRate.TaxType),
			TaxPeriodicity:                       LoansContractInterestRateTaxPeriodicity(interestRate.TaxPeriodicity),
			Calculation:                          LoansContractInterestRateCalculation(interestRate.Calculation),
			AdditionalInfo:                       interestRate.AdditionalInfo,
			ReferentialRateIndexerType:           LoansContractInterestRateReferentialRateIndexerType(interestRate.RateIndexerType),
			ReferentialRateIndexerAdditionalInfo: interestRate.RateIndexerAdditionalInfo,
		}

		if interestRate.FixedRate != nil {
			data.PreFixedRate = *interestRate.FixedRate
		}
		if interestRate.PostFixedRate != nil {
			data.PostFixedRate = *interestRate.PostFixedRate
		}
		if interestRate.RateIndexerSubType != nil {
			data.ReferentialRateIndexerSubType = pointerOf(EnumReferentialRateIndexerSubType(*interestRate.RateIndexerSubType))
		}
		resp.Data.ProposedContract.InterestRates = append(resp.Data.ProposedContract.InterestRates, data)
	}

	if portability.Rejection != nil {
		resp.Data.Rejection = &struct {
			Reason struct {
				Type               ResponsePortabilitiesByPortabilityIDDataRejectionReasonType `json:"type"`
				TypeAdditionalInfo *string                                                     `json:"typeAdditionalInfo,omitempty"`
			} `json:"reason"`
			RejectedBy ResponsePortabilitiesByPortabilityIDDataRejectionRejectedBy `json:"rejectedBy"`
		}{
			Reason: struct {
				Type               ResponsePortabilitiesByPortabilityIDDataRejectionReasonType `json:"type"`
				TypeAdditionalInfo *string                                                     `json:"typeAdditionalInfo,omitempty"`
			}{
				Type:               ResponsePortabilitiesByPortabilityIDDataRejectionReasonType(portability.Rejection.Reason),
				TypeAdditionalInfo: portability.Rejection.AdditionalInfo,
			},
			RejectedBy: ResponsePortabilitiesByPortabilityIDDataRejectionRejectedBy(portability.Rejection.By),
		}
	}

	if portability.StatusReason != nil {
		resp.Data.StatusReason = &struct {
			DigitalSignatureProof *struct {
				DocumentID        string `json:"documentId"`
				SignatureDateTime string `json:"signatureDateTime"`
			} `json:"digitalSignatureProof,omitempty"`
			ReasonType               *ResponsePortabilitiesByPortabilityIDDataStatusReasonReasonType `json:"reasonType,omitempty"`
			ReasonTypeAdditionalInfo *string                                                         `json:"reasonTypeAdditionalInfo,omitempty"`
		}{}

		if portability.StatusReason.ReasonType != nil {
			resp.Data.StatusReason.ReasonType = pointerOf(ResponsePortabilitiesByPortabilityIDDataStatusReasonReasonType(*portability.StatusReason.ReasonType))
		}
		if portability.StatusReason.ReasonTypeAdditionalInfo != nil {
			resp.Data.StatusReason.ReasonTypeAdditionalInfo = portability.StatusReason.ReasonTypeAdditionalInfo
		}
		if portability.StatusReason.DigitalSignatureProof != nil {
			resp.Data.StatusReason.DigitalSignatureProof = &struct {
				DocumentID        string `json:"documentId"`
				SignatureDateTime string `json:"signatureDateTime"`
			}{
				DocumentID:        portability.StatusReason.DigitalSignatureProof.DocumentID,
				SignatureDateTime: portability.StatusReason.DigitalSignatureProof.SignatureDateTime,
			}
		}
	}

	return CreditPortabilityGetPortabilitiesByPortabilityID200JSONResponse{OKResponsePortabilitiesByPortabilityIDJSONResponse(resp)}, nil
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
		Meta:  *api.NewMeta(),
		Links: *api.NewLinks(s.baseURL + "/portabilities/" + req.PortabilityID + "/account-data"),
	}
	return CreditPortabilityGetAccountData200JSONResponse{OKResponseAccountDataJSONResponse(resp)}, nil
}

func (s Server) CreditPortabilityPatchPortabilitiesPortabilityIDCancel(ctx context.Context, req CreditPortabilityPatchPortabilitiesPortabilityIDCancelRequestObject) (CreditPortabilityPatchPortabilitiesPortabilityIDCancelResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	portability, err := s.service.Cancel(ctx, string(req.PortabilityID), orgID, creditportability.Rejection{
		Reason:         creditportability.RejectionReason(req.Body.Data.Reason.Type),
		AdditionalInfo: req.Body.Data.Reason.TypeAdditionalInfo,
		By:             creditportability.RejectedBy(req.Body.Data.RejectedBy),
	})
	if err != nil {
		return nil, err
	}

	resp := PatchResponseCreditPortabilityCancel{
		Data: struct {
			Reason struct {
				Type               PatchResponseCreditPortabilityCancelDataReasonType `json:"type"`
				TypeAdditionalInfo *string                                            `json:"typeAdditionalInfo,omitempty"`
			} `json:"reason"`
			RejectedBy PatchResponseCreditPortabilityCancelDataRejectedBy `json:"rejectedBy"`
		}{
			Reason: struct {
				Type               PatchResponseCreditPortabilityCancelDataReasonType `json:"type"`
				TypeAdditionalInfo *string                                            `json:"typeAdditionalInfo,omitempty"`
			}{
				Type:               PatchResponseCreditPortabilityCancelDataReasonType(portability.Rejection.Reason),
				TypeAdditionalInfo: portability.Rejection.AdditionalInfo,
			},
			RejectedBy: PatchResponseCreditPortabilityCancelDataRejectedBy(portability.Rejection.By),
		},
		Meta: api.NewMeta(),
	}

	return CreditPortabilityPatchPortabilitiesPortabilityIDCancel200JSONResponse{PatchResponseCreditPortabilityCancelJSONResponse(resp)}, nil
}

func (s Server) CreditPortabilityPostPortabilitiesPortabilityIDPayment(ctx context.Context, req CreditPortabilityPostPortabilitiesPortabilityIDPaymentRequestObject) (CreditPortabilityPostPortabilitiesPortabilityIDPaymentResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)

	portability, err := s.service.CreatePayment(ctx, string(req.PortabilityID), orgID, creditportability.Payment{
		PortabilityID: string(req.PortabilityID),
		DateTime:      req.Body.Data.PaymentDateTime,
		Amount:        req.Body.Data.PaymentAmount.Amount,
		Currency:      req.Body.Data.PaymentAmount.Currency,
		TransactionID: req.Body.Data.TransactionID,
	})
	if err != nil {
		return nil, err
	}

	resp := POSTResponseCreditPortabilityPayment{
		Meta: api.NewMeta(),
	}

	if portability.Payment != nil {
		resp.Data = struct {
			PaymentAmount struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			} "json:\"paymentAmount\""
			PaymentDateTime timeutil.DateTime "json:\"paymentDateTime\""
			PortabilityID   string            "json:\"portabilityId\""
			TransactionID   string            "json:\"transactionId\""
		}{
			PaymentAmount: struct {
				Amount   string "json:\"amount\""
				Currency string "json:\"currency\""
			}{
				Amount:   portability.Payment.Amount,
				Currency: portability.Payment.Currency,
			},
			PaymentDateTime: portability.Payment.DateTime,
			PortabilityID:   portability.Payment.PortabilityID,
			TransactionID:   portability.Payment.TransactionID,
		}
	}

	return CreditPortabilityPostPortabilitiesPortabilityIDPayment202JSONResponse{POSTResponseCreditPortabilityPaymentJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, creditportability.ErrPortabilityInProgress) {
		api.WriteError(w, r, api.NewError("EM_ANDAMENTO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, creditportability.ErrContractNotEligible) {
		api.WriteError(w, r, api.NewError("CONTRATO_NAO_ELEGIVEL", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, creditportability.ErrIncompatibleInformation) {
		api.WriteError(w, r, api.NewError("CAMPO_INCONSISTENTE", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, creditportability.ErrIncompatibleInstalmentPeriodicity) {
		api.WriteError(w, r, api.NewError("PERIODICIDADE_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, creditportability.ErrInstalmentTermOverLimit) {
		api.WriteError(w, r, api.NewError("PRAZO_ACIMA_LIMITE", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.As(err, &errorutil.Error{}) {
		api.WriteError(w, r, api.NewError("NAO_INFORMADO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}

func pointerOf[T any](v T) *T {
	return &v
}
