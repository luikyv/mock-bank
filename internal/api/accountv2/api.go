//go:generate oapi-codegen -config=./config.yml -package=accountv2 -o=./api_gen.go ./swagger.yml
package accountv2

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/bank"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var _ StrictServerInterface = Server{}

type Server struct {
	baseURL        string
	service        account.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(host string, service account.Service, consentService consent.Service, op *provider.Provider) Server {
	return Server{
		baseURL:        host + "/open-banking/accounts/v2",
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	accountMux := http.NewServeMux()

	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID, consent.ScopeID)
	swaggerMiddleware, _ := middleware.Swagger(GetSwagger, func(err error) string { return "PARAMETRO_INVALIDO" })

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err, !strings.Contains(r.URL.Path, "/transactions-current"))
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{
			swaggerMiddleware,
			middleware.FAPIID(nil),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.AccountsGetAccounts)
	handler = middleware.Permission(s.consentService, consent.PermissionAccountsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	accountMux.Handle("GET /accounts", handler)

	handler = http.HandlerFunc(wrapper.AccountsGetAccountsAccountID)
	handler = middleware.Permission(s.consentService, consent.PermissionAccountsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	accountMux.Handle("GET /accounts/{accountId}", handler)

	handler = http.HandlerFunc(wrapper.AccountsGetAccountsAccountIDBalances)
	handler = middleware.Permission(s.consentService, consent.PermissionAccountsBalanceRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	accountMux.Handle("GET /accounts/{accountId}/balances", handler)

	handler = http.HandlerFunc(wrapper.AccountsGetAccountsAccountIDOverdraftLimits)
	handler = middleware.Permission(s.consentService, consent.PermissionAccountsOverdraftLimitsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	accountMux.Handle("GET /accounts/{accountId}/overdraft-limits", handler)

	handler = http.HandlerFunc(wrapper.AccountsGetAccountsAccountIDTransactions)
	handler = middleware.Permission(s.consentService, consent.PermissionAccountsTransactionsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	accountMux.Handle("GET /accounts/{accountId}/transactions", handler)

	handler = http.HandlerFunc(wrapper.AccountsGetAccountsAccountIDTransactionsCurrent)
	handler = middleware.Permission(s.consentService, consent.PermissionAccountsTransactionsRead)(handler)
	handler = authCodeAuthMiddleware(handler)
	accountMux.Handle("GET /accounts/{accountId}/transactions-current", handler)

	mux.Handle("/open-banking/accounts/v2/", http.StripPrefix("/open-banking/accounts/v2", accountMux))
}

func (s Server) AccountsGetAccounts(ctx context.Context, req AccountsGetAccountsRequestObject) (AccountsGetAccountsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	accs, err := s.service.ConsentedAccounts(ctx, consentID, orgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountList{
		Data:  []AccountData{},
		Meta:  *api.NewPaginatedMeta(accs),
		Links: *api.NewPaginatedLinks(s.baseURL+"/accounts", accs),
	}
	defaultBranch := account.DefaultBranch
	for _, acc := range accs.Records {
		resp.Data = append(resp.Data, AccountData{
			AccountID:   acc.ID.String(),
			BranchCode:  &defaultBranch,
			BrandName:   bank.Brand,
			CheckDigit:  account.DefaultCheckDigit,
			CompanyCnpj: bank.CNPJ,
			CompeCode:   account.DefaultCompeCode,
			Number:      acc.Number,
			Type:        EnumAccountType(acc.Type),
		})
	}

	return AccountsGetAccounts200JSONResponse{OKResponseAccountListJSONResponse: OKResponseAccountListJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountID(ctx context.Context, req AccountsGetAccountsAccountIDRequestObject) (AccountsGetAccountsAccountIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)

	acc, err := s.service.ConsentedAccount(ctx, req.AccountID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	defaultBranch := account.DefaultBranch
	resp := ResponseAccountIdentification{
		Data: AccountIdentificationData{
			BranchCode: &defaultBranch,
			CheckDigit: account.DefaultCheckDigit,
			CompeCode:  account.DefaultCompeCode,
			Currency:   bank.Currency,
			Number:     acc.Number,
			Subtype:    EnumAccountSubType(acc.SubType),
			Type:       EnumAccountType(acc.Type),
		},
		Meta:  *api.NewSingleRecordMeta(),
		Links: *api.NewLinks(s.baseURL + "/accounts/" + req.AccountID),
	}
	return AccountsGetAccountsAccountID200JSONResponse{OKResponseAccountIdentificationJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDBalances(ctx context.Context, req AccountsGetAccountsAccountIDBalancesRequestObject) (AccountsGetAccountsAccountIDBalancesResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)

	acc, err := s.service.ConsentedAccount(ctx, req.AccountID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountBalances{
		Data: AccountBalancesData{
			AutomaticallyInvestedAmount: AccountBalancesDataAutomaticallyInvestedAmount{
				Amount:   acc.AvailableAmount,
				Currency: bank.Currency,
			},
			AvailableAmount: AccountBalancesDataAvailableAmount{
				Amount:   acc.AvailableAmount,
				Currency: bank.Currency,
			},
			BlockedAmount: AccountBalancesDataBlockedAmount{
				Amount:   acc.BlockedAmount,
				Currency: bank.Currency,
			},
			UpdateDateTime: acc.UpdatedAt,
		},
		Meta:  *api.NewSingleRecordMeta(),
		Links: *api.NewLinks(s.baseURL + "/accounts/" + req.AccountID + "/balances"),
	}
	return AccountsGetAccountsAccountIDBalances200JSONResponse{OKResponseAccountBalancesJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDOverdraftLimits(ctx context.Context, req AccountsGetAccountsAccountIDOverdraftLimitsRequestObject) (AccountsGetAccountsAccountIDOverdraftLimitsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)

	acc, err := s.service.ConsentedAccount(ctx, req.AccountID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountOverdraftLimits{
		Meta:  *api.NewSingleRecordMeta(),
		Links: *api.NewLinks(s.baseURL + "/accounts/" + req.AccountID + "/overdraft-limits"),
	}
	if acc.OverdraftLimitContracted != "" {
		resp.Data.OverdraftContractedLimit = &AccountOverdraftLimitsDataOverdraftContractedLimit{
			Amount:   acc.OverdraftLimitContracted,
			Currency: bank.Currency,
		}
	}
	if acc.OverdraftLimitUsed != "" {
		resp.Data.OverdraftUsedLimit = &AccountOverdraftLimitsDataOverdraftUsedLimit{
			Amount:   acc.OverdraftLimitUsed,
			Currency: bank.Currency,
		}
	}
	if acc.OverdraftLimitUnarranged != "" {
		resp.Data.UnarrangedOverdraftAmount = &AccountOverdraftLimitsDataUnarrangedOverdraftAmount{
			Amount:   acc.OverdraftLimitUnarranged,
			Currency: bank.Currency,
		}
	}

	return AccountsGetAccountsAccountIDOverdraftLimits200JSONResponse{OKResponseAccountOverdraftLimitsJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDTransactions(ctx context.Context, req AccountsGetAccountsAccountIDTransactionsRequestObject) (AccountsGetAccountsAccountIDTransactionsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	filter, err := account.NewTransactionFilter(req.Params.FromBookingDate, req.Params.ToBookingDate, false)
	if err != nil {
		return nil, err
	}

	if req.Params.CreditDebitIndicator != nil {
		filter = filter.WithMovementType(account.MovementType(*req.Params.CreditDebitIndicator))
	}

	txs, err := s.service.ConsentedTransactions(ctx, req.AccountID, consentID, orgID, pag, filter)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountTransactions{
		Data:  []AccountTransactionsData{},
		Meta:  *api.NewMeta(),
		Links: *api.NewPaginatedLinks(s.baseURL+"/accounts/"+req.AccountID+"/transactions", txs),
	}
	for _, tx := range txs.Records {
		data := AccountTransactionsData{
			CompletedAuthorisedPaymentType: EnumCompletedAuthorisedPaymentIndicator(tx.Status),
			CreditDebitType:                EnumCreditDebitIndicator(tx.MovementType),
			PartieBranchCode:               tx.PartieBranchCode,
			PartieCheckDigit:               tx.PartieCheckDigit,
			PartieCnpjCpf:                  tx.PartieCNPJCPF,
			PartieCompeCode:                tx.PartieCompeCode,
			PartieNumber:                   tx.PartieNumber,
			TransactionAmount: AccountTransactionsDataAmount{
				Amount:   tx.Amount,
				Currency: bank.Currency,
			},
			TransactionDateTime: tx.CreatedAt.Format(timeutil.DateTimeMillisFormat),
			TransactionID:       tx.ID,
			TransactionName:     tx.Name,
			Type:                EnumTransactionTypes(tx.Type),
		}
		if tx.PartiePersonType != nil {
			partiePersonType := EnumPartiePersonType(*tx.PartiePersonType)
			data.PartiePersonType = &partiePersonType
		}
		resp.Data = append(resp.Data, data)
	}
	return AccountsGetAccountsAccountIDTransactions200JSONResponse{OKResponseAccountTransactionsJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDTransactionsCurrent(ctx context.Context, req AccountsGetAccountsAccountIDTransactionsCurrentRequestObject) (AccountsGetAccountsAccountIDTransactionsCurrentResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	filter, err := account.NewTransactionFilter(req.Params.FromBookingDate, req.Params.ToBookingDate, false)
	if err != nil {
		return nil, err
	}

	if req.Params.CreditDebitIndicator != nil {
		filter = filter.WithMovementType(account.MovementType(*req.Params.CreditDebitIndicator))
	}

	txs, err := s.service.ConsentedTransactions(ctx, req.AccountID, consentID, orgID, pag, filter)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountTransactions{
		Data:  []AccountTransactionsData{},
		Meta:  *api.NewMeta(),
		Links: *api.NewPaginatedLinks(s.baseURL+"/accounts/"+req.AccountID+"/transactions-current", txs),
	}
	for _, tx := range txs.Records {
		data := AccountTransactionsData{
			CompletedAuthorisedPaymentType: EnumCompletedAuthorisedPaymentIndicator(tx.Status),
			CreditDebitType:                EnumCreditDebitIndicator(tx.MovementType),
			PartieBranchCode:               tx.PartieBranchCode,
			PartieCheckDigit:               tx.PartieCheckDigit,
			PartieCnpjCpf:                  tx.PartieCNPJCPF,
			PartieCompeCode:                tx.PartieCompeCode,
			PartieNumber:                   tx.PartieNumber,
			TransactionAmount: AccountTransactionsDataAmount{
				Amount:   tx.Amount,
				Currency: bank.Currency,
			},
			TransactionDateTime: tx.CreatedAt.Format(timeutil.DateTimeMillisFormat),
			TransactionID:       tx.ID,
			TransactionName:     tx.Name,
			Type:                EnumTransactionTypes(tx.Type),
		}
		if tx.PartiePersonType != nil {
			partiePersonType := EnumPartiePersonType(*tx.PartiePersonType)
			data.PartiePersonType = &partiePersonType
		}
		resp.Data = append(resp.Data, data)
	}

	return AccountsGetAccountsAccountIDTransactionsCurrent200JSONResponse{OKResponseAccountTransactionsJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error, pagination bool) {
	if errors.Is(err, account.ErrNotAllowed) {
		api.WriteError(w, r, api.NewError("FORBIDDEN", http.StatusForbidden, account.ErrNotAllowed.Error()).Pagination(pagination))
		return
	}

	if errors.Is(err, account.ErrJointAccountPendingAuthorization) {
		api.WriteError(w, r, api.NewError("STATUS_RESOURCE_PENDING_AUTHORISATION", http.StatusForbidden, account.ErrJointAccountPendingAuthorization.Error()).Pagination(pagination))
		return
	}

	api.WriteError(w, r, err)
}
