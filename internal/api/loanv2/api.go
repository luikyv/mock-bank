//go:generate oapi-codegen -config=./config.yml -package=loanv2 -o=./api_gen.go ./swagger.yml
package loanv2

import (
	"context"
	"errors"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
)

var _ StrictServerInterface = Server{}

type BankConfig interface {
	Host() string
	Brand() string
	CNPJ() string
}

type Server struct {
	config         BankConfig
	baseURL        string
	service        creditop.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(
	config BankConfig,
	service creditop.Service,
	consentService consent.Service,
	op *provider.Provider,
) Server {
	return Server{
		config:         config,
		baseURL:        config.Host() + "/open-banking/loans/v2",
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	loanMux := http.NewServeMux()

	middlewareOpts := &middleware.Options{ErrorPagination: true}
	authCodeAuthMiddleware := middleware.AuthWithOptions(
		s.op,
		goidc.GrantAuthorizationCode,
		middlewareOpts,
		goidc.ScopeOpenID,
		consent.ScopeID,
	)
	swaggerMiddleware, _ := middleware.Swagger(GetSwagger, func(err error) api.Error {
		return api.NewError("PARAMETRO_INVALIDO", http.StatusBadRequest, err.Error())
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

	handler = http.HandlerFunc(wrapper.LoansGetContracts)
	handler = middleware.PermissionWithOptions(s.consentService, middlewareOpts, consent.PermissionLoansRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	loanMux.Handle("GET /contracts", handler)

	handler = http.HandlerFunc(wrapper.LoansGetContractsContractID)
	handler = middleware.PermissionWithOptions(s.consentService, middlewareOpts, consent.PermissionLoansRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	loanMux.Handle("GET /contracts/{contractId}", handler)

	handler = http.HandlerFunc(wrapper.LoansGetContractsContractIDWarranties)
	handler = middleware.PermissionWithOptions(s.consentService, middlewareOpts, consent.PermissionLoansWarrantiesRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	loanMux.Handle("GET /contracts/{contractId}/warranties", handler)

	handler = http.HandlerFunc(wrapper.LoansGetContractsContractIDPayments)
	handler = middleware.PermissionWithOptions(s.consentService, middlewareOpts, consent.PermissionLoansPaymentsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	loanMux.Handle("GET /contracts/{contractId}/payments", handler)

	handler = http.HandlerFunc(wrapper.LoansGetContractsContractIDScheduledInstalments)
	handler = middleware.PermissionWithOptions(s.consentService, middlewareOpts, consent.PermissionLoansScheduledInstalmentsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	loanMux.Handle("GET /contracts/{contractId}/scheduled-instalments", handler)

	handler = middleware.FAPIIDWithOptions(middlewareOpts)(loanMux)
	mux.Handle("/open-banking/loans/v2/", http.StripPrefix("/open-banking/loans/v2", handler))
}

func (s Server) LoansGetContracts(ctx context.Context, req LoansGetContractsRequestObject) (LoansGetContractsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	loans, err := s.service.ConsentedContracts(ctx, consentID, orgID, resource.TypeLoan, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseLoansContractList{
		Data:  []LoansListContract{},
		Meta:  *api.NewPaginatedMeta(loans),
		Links: *api.NewPaginatedLinks(s.baseURL+"/contracts", loans),
	}
	for _, loan := range loans.Records {
		resp.Data = append(resp.Data, LoansListContract{
			BrandName:      s.config.Brand(),
			CompanyCnpj:    s.config.CNPJ(),
			ContractID:     loan.ID.String(),
			IpocCode:       loan.IPOCCode,
			ProductSubType: EnumContractProductSubTypeLoans(loan.ProductSubType),
			ProductType:    EnumContractProductTypeLoans(loan.ProductType),
		})
	}

	return LoansGetContracts200JSONResponse{OKResponseLoansContractListJSONResponse(resp)}, nil
}

func (s Server) LoansGetContractsContractID(ctx context.Context, req LoansGetContractsContractIDRequestObject) (LoansGetContractsContractIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)

	loan, err := s.service.ConsentedContract(ctx, req.ContractID, consentID, orgID, resource.TypeLoan)
	if err != nil {
		return nil, err
	}

	resp := ResponseLoansContract{
		Data: LoansContract{
			CET:                                 loan.CET,
			AmortizationScheduled:               EnumContractAmortizationScheduled(loan.AmortizationSchedule),
			AmortizationScheduledAdditionalInfo: loan.AmortizationScheduleAdditionalInfo,
			CnpjConsignee:                       loan.CNPJConsignee,
			ContractAmount:                      loan.Amount,
			ContractDate:                        loan.Date,
			ContractNumber:                      loan.Number,
			Currency:                            loan.Currency,
			DisbursementDates:                   loan.DisbursementDates,
			DueDate:                             loan.DueDate,
			FirstInstalmentDueDate:              loan.FirstInstalmentDueDate,
			InstalmentPeriodicity:               EnumContractInstalmentPeriodicity(loan.InstalmentPeriodicity),
			InstalmentPeriodicityAdditionalInfo: loan.InstalmentPeriodicityAdditionalInfo,
			InterestRates:                       []LoansContractInterestRate{},
			IpocCode:                            loan.IPOCCode,
			ProductName:                         loan.ProductName,
			ProductSubType:                      EnumContractProductSubTypeLoans(loan.ProductSubType),
			ProductType:                         EnumContractProductTypeLoans(loan.ProductType),
			SettlementDate:                      loan.SettlementDate,
			ContractedFees:                      []LoansContractedFee{},
			ContractedFinanceCharges:            []LoansFinanceCharge{},
		},
		Links: *api.NewLinks(s.baseURL + "/contracts/" + req.ContractID),
		Meta:  *api.NewSingleRecordMeta(),
	}

	for _, fee := range loan.ContractedFees {
		resp.Data.ContractedFees = append(resp.Data.ContractedFees, LoansContractedFee{
			FeeAmount:     fee.Amount,
			FeeCharge:     EnumContractFeeCharge(fee.ChargeCalculation),
			FeeChargeType: EnumContractFeeChargeType(fee.ChargeType),
			FeeCode:       fee.Code,
			FeeName:       fee.Name,
			FeeRate:       fee.Rate,
		})
	}

	for _, financeCharge := range loan.FinanceCharges {
		resp.Data.ContractedFinanceCharges = append(resp.Data.ContractedFinanceCharges, LoansFinanceCharge{
			ChargeAdditionalInfo: financeCharge.AdditionalInfo,
			ChargeRate:           financeCharge.Rate,
			ChargeType:           EnumContractFinanceChargeType(financeCharge.Type),
		})
	}

	for _, interestRate := range loan.InterestRates {
		data := LoansContractInterestRate{
			AdditionalInfo:                       interestRate.AdditionalInfo,
			Calculation:                          EnumContractCalculation(interestRate.Calculation),
			InterestRateType:                     EnumContractInterestRateType(interestRate.Type),
			ReferentialRateIndexerAdditionalInfo: interestRate.RateIndexerAdditionalInfo,
			ReferentialRateIndexerType:           EnumContractReferentialRateIndexerType(interestRate.RateIndexerType),
			TaxPeriodicity:                       EnumContractTaxPeriodicity(interestRate.TaxPeriodicity),
			TaxType:                              EnumContractTaxType(interestRate.TaxType),
		}

		if interestRate.RateIndexerSubType != nil {
			subType := EnumContractReferentialRateIndexerSubType(*interestRate.RateIndexerSubType)
			data.ReferentialRateIndexerSubType = &subType
		}

		if interestRate.PostFixedRate != nil {
			data.PostFixedRate = *interestRate.PostFixedRate
		}

		if interestRate.FixedRate != nil {
			data.PreFixedRate = *interestRate.FixedRate
		}

		resp.Data.InterestRates = append(resp.Data.InterestRates, data)
	}

	return LoansGetContractsContractID200JSONResponse{OKResponseLoansContractJSONResponse(resp)}, nil
}

func (s Server) LoansGetContractsContractIDPayments(ctx context.Context, req LoansGetContractsContractIDPaymentsRequestObject) (LoansGetContractsContractIDPaymentsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	contract, payments, err := s.service.ConsentedRealesePayments(ctx, req.ContractID, consentID, orgID, resource.TypeLoan, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseLoansPayments{
		Data: LoansPayments{
			ContractOutstandingBalance: contract.OutstandingBalance,
			Releases:                   []LoansReleases{},
		},
		Meta:  *api.NewPaginatedMeta(payments),
		Links: *api.NewPaginatedLinks(s.baseURL+"/contracts/"+req.ContractID+"/payments", payments),
	}
	if contract.PaidInstalments != nil {
		paidInstalments := float32(*contract.PaidInstalments)
		resp.Data.PaidInstalments = &paidInstalments
	}
	for _, payment := range payments.Records {
		data := LoansReleases{
			Currency:            payment.Currency,
			InstalmentID:        payment.InstalmentID,
			IsOverParcelPayment: payment.IsOverParcelPayment,
			PaidAmount:          payment.Amount,
			PaidDate:            payment.Date,
			PaymentID:           payment.ID.String(),
		}
		if payment.OverParcel != nil {
			data.OverParcel = &struct {
				Charges []LoansChargeOverParcel `json:"charges"`
				Fees    []LoansFeeOverParcel    `json:"fees"`
			}{}
			for _, charge := range payment.OverParcel.Charges {
				data.OverParcel.Charges = append(data.OverParcel.Charges, LoansChargeOverParcel{
					ChargeAmount:         charge.Amount,
					ChargeType:           EnumContractFinanceChargeType(charge.Type),
					ChargeAdditionalInfo: charge.AdditionalInfo,
				})
			}
			for _, fee := range payment.OverParcel.Fees {
				data.OverParcel.Fees = append(data.OverParcel.Fees, LoansFeeOverParcel{
					FeeAmount: fee.Amount,
					FeeCode:   fee.Code,
					FeeName:   fee.Name,
				})
			}
		}
		resp.Data.Releases = append(resp.Data.Releases, data)
	}
	return LoansGetContractsContractIDPayments200JSONResponse{OKResponseLoansPaymentsJSONResponse(resp)}, nil
}

func (s Server) LoansGetContractsContractIDScheduledInstalments(ctx context.Context, req LoansGetContractsContractIDScheduledInstalmentsRequestObject) (LoansGetContractsContractIDScheduledInstalmentsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	contract, balloonPayments, err := s.service.ConsentedBalloonPayments(ctx, req.ContractID, consentID, orgID, resource.TypeLoan, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseLoansInstalments{
		Data: LoansInstalments{
			DueInstalments:          float32(contract.DueInstalments),
			PastDueInstalments:      float32(contract.PastDueInstalments),
			TypeContractRemaining:   LoansInstalmentsTypeContractRemaining(contract.RemainingInstalmentType),
			TypeNumberOfInstalments: LoansInstalmentsTypeNumberOfInstalments(contract.TotalInstalmentType),
		},
		Meta:  *api.NewPaginatedMeta(balloonPayments),
		Links: *api.NewPaginatedLinks(s.baseURL+"/contracts/"+req.ContractID+"/scheduled-instalments", balloonPayments),
	}

	if contract.PaidInstalments != nil {
		resp.Data.PaidInstalments = float32(*contract.PaidInstalments)
	}

	if contract.TotalInstalments != nil {
		totalInstalments := float32(*contract.TotalInstalments)
		resp.Data.TotalNumberOfInstalments = &totalInstalments
	}

	if contract.RemainingInstalments != nil {
		remainingInstalments := float32(*contract.RemainingInstalments)
		resp.Data.ContractRemainingNumber = &remainingInstalments
	}

	balloonPaymentsData := []LoansBalloonPayment{}
	for _, balloonPayment := range balloonPayments.Records {
		balloonPaymentsData = append(balloonPaymentsData, LoansBalloonPayment{
			Amount: LoansBalloonPaymentAmount{
				Amount:   balloonPayment.Amount,
				Currency: balloonPayment.Currency,
			},
			DueDate: balloonPayment.DueDate,
		})
	}

	resp.Data.BalloonPayments = &balloonPaymentsData

	return LoansGetContractsContractIDScheduledInstalments200JSONResponse{OKResponseLoansInstalmentsJSONResponse(resp)}, nil
}

func (s Server) LoansGetContractsContractIDWarranties(ctx context.Context, req LoansGetContractsContractIDWarrantiesRequestObject) (LoansGetContractsContractIDWarrantiesResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	warranties, err := s.service.ConsentedWarranties(ctx, req.ContractID, consentID, orgID, resource.TypeLoan, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseLoansWarranties{
		Data:  []LoansWarranties{},
		Meta:  *api.NewPaginatedMeta(warranties),
		Links: *api.NewPaginatedLinks(s.baseURL+"/contracts/"+req.ContractID+"/warranties", warranties),
	}

	for _, warranty := range warranties.Records {
		data := LoansWarranties{
			Currency:        warranty.Currency,
			WarrantyAmount:  warranty.Amount,
			WarrantySubType: EnumWarrantySubType(warranty.SubType),
			WarrantyType:    EnumWarrantyType(warranty.Type),
		}
		resp.Data = append(resp.Data, data)
	}

	return LoansGetContractsContractIDWarranties200JSONResponse{OKResponseLoansWarrantiesJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, creditop.ErrNotAllowed) {
		api.WriteError(w, r, api.NewError("FORBIDDEN", http.StatusForbidden, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}
