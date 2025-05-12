package v2

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/config"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/middleware"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

var _ StrictServerInterface = Server{}

type Server struct {
	host           string
	service        account.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(host string, service account.Service, consentService consent.Service, op *provider.Provider) Server {
	return Server{
		host:           host,
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	strictHandler := NewStrictHandlerWithOptions(s, []StrictMiddlewareFunc{
		middleware.FAPIID(map[string]middleware.Options{
			"accountsGetAccounts":                         {ErrorPagination: true},
			"accountsGetAccountsAccountId":                {ErrorPagination: true},
			"accountsGetAccountsAccountIdBalances":        {ErrorPagination: true},
			"accountsGetAccountsAccountIdOverdraftLimits": {ErrorPagination: true},
			"accountsGetAccountsAccountIdTransactions":    {ErrorPagination: true},
		}),
		middleware.Meta(s.host),
		middleware.AuthScopes(map[string]middleware.AuthOptions{
			"accountsGetAccounts":                             {Scopes: []goidc.Scope{goidc.ScopeOpenID, consent.ScopeID}, ErrorPagination: true},
			"accountsGetAccountsAccountId":                    {Scopes: []goidc.Scope{goidc.ScopeOpenID, consent.ScopeID}, ErrorPagination: true},
			"accountsGetAccountsAccountIdBalances":            {Scopes: []goidc.Scope{goidc.ScopeOpenID, consent.ScopeID}, ErrorPagination: true},
			"accountsGetAccountsAccountIdOverdraftLimits":     {Scopes: []goidc.Scope{goidc.ScopeOpenID, consent.ScopeID}, ErrorPagination: true},
			"accountsGetAccountsAccountIdTransactions":        {Scopes: []goidc.Scope{goidc.ScopeOpenID, consent.ScopeID}, ErrorPagination: true},
			"accountsGetAccountsAccountIdTransactionsCurrent": {Scopes: []goidc.Scope{goidc.ScopeOpenID, consent.ScopeID}},
		}, s.op),
		consent.PermissionMiddleware(map[string]consent.PermissionOptions{
			"accountsGetAccounts":                             {Permissions: []consent.Permission{consent.PermissionAccountsRead}, ErrorPagination: true},
			"accountsGetAccountsAccountId":                    {Permissions: []consent.Permission{consent.PermissionAccountsRead}, ErrorPagination: true},
			"accountsGetAccountsAccountIdBalances":            {Permissions: []consent.Permission{consent.PermissionAccountsBalanceRead}, ErrorPagination: true},
			"accountsGetAccountsAccountIdOverdraftLimits":     {Permissions: []consent.Permission{consent.PermissionAccountsOverdraftLimitsRead}, ErrorPagination: true},
			"accountsGetAccountsAccountIdTransactions":        {Permissions: []consent.Permission{consent.PermissionAccountsTransactionsRead}, ErrorPagination: true},
			"accountsGetAccountsAccountIdTransactionsCurrent": {Permissions: []consent.Permission{consent.PermissionAccountsTransactionsRead}},
		}, s.consentService),
	}, StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			isTransactionCurrent := strings.HasSuffix(r.URL.Path, "/transactions-current")
			writeResponseError(w, err, !isTransactionCurrent)
		},
	})
	handler := Handler(strictHandler)
	mux.Handle("/open-banking/accounts/v2/", http.StripPrefix("/open-banking/accounts/v2", handler))
}

func (s Server) AccountsGetAccounts(ctx context.Context, req AccountsGetAccountsRequestObject) (AccountsGetAccountsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	accs, err := s.service.ConsentedAccounts(ctx, consentID, orgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountList{
		Data:  []AccountData{},
		Meta:  *api.NewPaginatedMeta(accs),
		Links: *api.NewPaginatedLinks(reqURL, accs),
	}
	defaultBranch := account.DefaultBranch
	for _, acc := range accs.Records {
		resp.Data = append(resp.Data, AccountData{
			AccountID:   acc.ID,
			BranchCode:  &defaultBranch,
			BrandName:   config.MockBankBrand,
			CheckDigit:  account.DefaultCheckDigit,
			CompanyCnpj: config.MockBankCNPJ,
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
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)

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
			Currency:   config.DefaultCurrency,
			Number:     acc.Number,
			Subtype:    EnumAccountSubType(acc.SubType),
			Type:       EnumAccountType(acc.Type),
		},
		Meta:  *api.NewSingleRecordMeta(),
		Links: *api.NewLinks(reqURL),
	}
	return AccountsGetAccountsAccountID200JSONResponse{OKResponseAccountIdentificationJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDBalances(ctx context.Context, req AccountsGetAccountsAccountIDBalancesRequestObject) (AccountsGetAccountsAccountIDBalancesResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)

	acc, err := s.service.ConsentedAccount(ctx, req.AccountID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountBalances{
		Data: AccountBalancesData{
			AutomaticallyInvestedAmount: AccountBalancesDataAutomaticallyInvestedAmount{
				Amount:   acc.AvailableAmount,
				Currency: config.DefaultCurrency,
			},
			AvailableAmount: AccountBalancesDataAvailableAmount{
				Amount:   acc.AvailableAmount,
				Currency: config.DefaultCurrency,
			},
			BlockedAmount: AccountBalancesDataBlockedAmount{
				Amount:   acc.BlockedAmount,
				Currency: config.DefaultCurrency,
			},
			UpdateDateTime: timex.NewDateTime(acc.UpdatedAt),
		},
		Meta:  *api.NewSingleRecordMeta(),
		Links: *api.NewLinks(reqURL),
	}
	return AccountsGetAccountsAccountIDBalances200JSONResponse{OKResponseAccountBalancesJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDOverdraftLimits(ctx context.Context, req AccountsGetAccountsAccountIDOverdraftLimitsRequestObject) (AccountsGetAccountsAccountIDOverdraftLimitsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)

	acc, err := s.service.ConsentedAccount(ctx, req.AccountID, consentID, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountOverdraftLimits{
		Meta:  *api.NewSingleRecordMeta(),
		Links: *api.NewLinks(reqURL),
	}
	if acc.OverdraftLimitContracted != "" {
		resp.Data.OverdraftContractedLimit = &AccountOverdraftLimitsDataOverdraftContractedLimit{
			Amount:   acc.OverdraftLimitContracted,
			Currency: config.DefaultCurrency,
		}
	}
	if acc.OverdraftLimitUsed != "" {
		resp.Data.OverdraftUsedLimit = &AccountOverdraftLimitsDataOverdraftUsedLimit{
			Amount:   acc.OverdraftLimitUsed,
			Currency: config.DefaultCurrency,
		}
	}
	if acc.OverdraftLimitUnarranged != "" {
		resp.Data.UnarrangedOverdraftAmount = &AccountOverdraftLimitsDataUnarrangedOverdraftAmount{
			Amount:   acc.OverdraftLimitUnarranged,
			Currency: config.DefaultCurrency,
		}
	}

	return AccountsGetAccountsAccountIDOverdraftLimits200JSONResponse{OKResponseAccountOverdraftLimitsJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDTransactions(ctx context.Context, req AccountsGetAccountsAccountIDTransactionsRequestObject) (AccountsGetAccountsAccountIDTransactionsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	filter, err := account.NewTransactionFilter(req.Params.FromBookingDate, req.Params.ToBookingDate, false)
	if err != nil {
		return nil, err
	}

	txs, err := s.service.ConsentedTransactions(ctx, req.AccountID, consentID, orgID, pag, filter)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountTransactions{
		Data:  []AccountTransactionsData{},
		Meta:  *api.NewPaginatedMeta(txs),
		Links: *api.NewPaginatedLinks(reqURL, txs),
	}
	for _, tx := range txs.Records {
		resp.Data = append(resp.Data, AccountTransactionsData{
			CompletedAuthorisedPaymentType: EnumCompletedAuthorisedPaymentIndicator(tx.Status),
			CreditDebitType:                EnumCreditDebitIndicator(tx.MovementType),
			// PartieBranchCode:               "",
			// PartieCheckDigit:               "",
			// PartieCnpjCpf:                  "",
			// PartieCompeCode:                "",
			// PartieNumber:                   "",
			// PartiePersonType:               "",
			TransactionAmount: AccountTransactionsDataAmount{
				Amount:   tx.Amount,
				Currency: config.DefaultCurrency,
			},
			TransactionDateTime: tx.CreatedAt.Format(timex.DateTimeMillisFormat),
			TransactionID:       tx.ID,
			TransactionName:     tx.Name,
			Type:                EnumTransactionTypes(tx.Type),
		})
	}
	return AccountsGetAccountsAccountIDTransactions200JSONResponse{OKResponseAccountTransactionsJSONResponse(resp)}, nil
}

func (s Server) AccountsGetAccountsAccountIDTransactionsCurrent(ctx context.Context, req AccountsGetAccountsAccountIDTransactionsCurrentRequestObject) (AccountsGetAccountsAccountIDTransactionsCurrentResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	filter, err := account.NewTransactionFilter(req.Params.FromBookingDate, req.Params.ToBookingDate, false)
	if err != nil {
		return nil, err
	}

	txs, err := s.service.ConsentedTransactions(ctx, req.AccountID, consentID, orgID, pag, filter)
	if err != nil {
		return nil, err
	}

	resp := ResponseAccountTransactions{
		Data:  []AccountTransactionsData{},
		Meta:  *api.NewPaginatedMeta(txs),
		Links: *api.NewPaginatedLinks(reqURL, txs),
	}
	for _, tx := range txs.Records {
		resp.Data = append(resp.Data, AccountTransactionsData{
			CompletedAuthorisedPaymentType: EnumCompletedAuthorisedPaymentIndicator(tx.Status),
			CreditDebitType:                EnumCreditDebitIndicator(tx.MovementType),
			// PartieBranchCode:               "",
			// PartieCheckDigit:               "",
			// PartieCnpjCpf:                  "",
			// PartieCompeCode:                "",
			// PartieNumber:                   "",
			// PartiePersonType:               "",
			TransactionAmount: AccountTransactionsDataAmount{
				Amount:   tx.Amount,
				Currency: config.DefaultCurrency,
			},
			TransactionDateTime: tx.CreatedAt.Format(timex.DateTimeMillisFormat),
			TransactionID:       tx.ID,
			TransactionName:     tx.Name,
			Type:                EnumTransactionTypes(tx.Type),
		})
	}

	return AccountsGetAccountsAccountIDTransactionsCurrent200JSONResponse{OKResponseAccountTransactionsJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, err error, pagination bool) {
	if errors.Is(err, account.ErrNotAllowed) {
		api.WriteError(w, api.NewError("FORBIDDEN", http.StatusForbidden, account.ErrNotAllowed.Error()).Pagination(pagination))
		return
	}

	if errors.Is(err, account.ErrJointAccountPendingAuthorization) {
		api.WriteError(w, api.NewError("STATUS_RESOURCE_PENDING_AUTHORISATION", http.StatusForbidden, account.ErrJointAccountPendingAuthorization.Error()).Pagination(pagination))
		return
	}

	api.WriteError(w, err)
}
