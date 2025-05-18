package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/user"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
	netmiddleware "github.com/oapi-codegen/nethttp-middleware"
	"github.com/rs/cors"
)

var _ StrictServerInterface = Server{}

type Server struct {
	host             string
	service          Service
	directoryService DirectoryService
	userService      user.Service
	consentService   consent.Service
	accountService   account.Service
}

func NewServer(
	host string,
	service Service,
	directoryService DirectoryService,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
) Server {
	return Server{
		host:             host,
		service:          service,
		directoryService: directoryService,
		userService:      userService,
		consentService:   consentService,
		accountService:   accountService,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {

	appMux := http.NewServeMux()

	spec, err := GetSwagger()
	if err != nil {
		panic(err)
	}
	spec.Servers = nil
	swaggerMiddleware := netmiddleware.OapiRequestValidatorWithOptions(spec, &netmiddleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
		ErrorHandler: func(w http.ResponseWriter, message string, _ int) {
			api.WriteError(w, api.NewError("INVALID_REQUEST", http.StatusBadRequest, message))
		},
	})

	strictHandler := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeResponseError(w, err)
		},
	})
	wrapper := ServerInterfaceWrapper{
		Handler:            strictHandler,
		HandlerMiddlewares: []MiddlewareFunc{swaggerMiddleware, interactionIDMiddleware},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	appMux.HandleFunc("GET /api/directory/auth-url", wrapper.GetDirectoryAuthURL)
	appMux.HandleFunc("GET /api/directory/callback", wrapper.HandleDirectoryCallback)
	appMux.HandleFunc("GET /api/directory/jwks", func(w http.ResponseWriter, r *http.Request) {
		api.WriteJSON(w, s.directoryService.publicJWKS(), http.StatusOK)
	})
	appMux.HandleFunc("POST /api/logout", wrapper.LogoutUser)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.GetCurrentUser), s.service)
	appMux.Handle("GET /api/me", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.GetMockUsers), s.service)
	appMux.Handle("GET /api/orgs/{orgId}/users", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.CreateMockUser), s.service)
	appMux.Handle("POST /api/orgs/{orgId}/users", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.DeleteMockUser), s.service)
	appMux.Handle("DELETE /api/orgs/{orgId}/users/{userId}", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.UpdateMockUser), s.service)
	appMux.Handle("PUT /api/orgs/{orgId}/users/{userId}", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.GetAccounts), s.service)
	appMux.Handle("GET /api/orgs/{orgId}/users/{userId}/accounts", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.CreateAccount), s.service)
	appMux.Handle("POST /api/orgs/{orgId}/users/{userId}/accounts", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.DeleteAccount), s.service)
	appMux.Handle("DELETE /api/orgs/{orgId}/users/{userId}/accounts/{accountId}", handler)

	handler = authMiddlewareHandler(http.HandlerFunc(wrapper.GetConsents), s.service)
	appMux.Handle("GET /api/orgs/{orgId}/users/{userId}/consents", handler)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{s.host},
		AllowCredentials: true,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodDelete,
			http.MethodPut,
		},
	})
	mux.Handle("/api/", c.Handler(appMux))
}

func writeResponseError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSessionNotFound) {
		api.WriteError(w, api.NewError("UNAUTHORIZED", http.StatusUnauthorized, err.Error()))
		return
	}

	if errors.Is(err, user.ErrAlreadyExists) {
		api.WriteError(w, api.NewError("USER_ALREADY_EXISTS", http.StatusBadRequest, err.Error()))
		return
	}

	if errors.Is(err, account.ErrAlreadyExists) {
		api.WriteError(w, api.NewError("ACCOUNT_ALREADY_EXISTS", http.StatusBadRequest, err.Error()))
		return
	}

	api.WriteError(w, err)
}

func (s Server) GetDirectoryAuthURL(ctx context.Context, request GetDirectoryAuthURLRequestObject) (GetDirectoryAuthURLResponseObject, error) {

	authURL, nonceHash, err := s.directoryService.authURL(ctx)
	if err != nil {
		return nil, err
	}

	headers := GetDirectoryAuthURL200ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieNonce,
			Value:    nonceHash,
			Path:     "/api/directory/callback",
			Expires:  timex.Now().Add(nonceValidity),
			HttpOnly: true,
			Secure:   true,
			Domain:   strings.TrimPrefix(s.host, "https://"),
			SameSite: http.SameSiteStrictMode,
		}).String(),
	}

	resp := AuthURLResponse{
		Data: struct {
			URL string `json:"url"`
		}{
			URL: authURL,
		},
	}
	return GetDirectoryAuthURL200JSONResponse{Headers: headers, Body: resp}, nil
}

func (s Server) HandleDirectoryCallback(ctx context.Context, req HandleDirectoryCallbackRequestObject) (HandleDirectoryCallbackResponseObject, error) {
	session, err := s.service.createSession(ctx, req.Params.IDToken, req.Params.Nonce)
	if err != nil {
		return nil, err
	}

	headers := HandleDirectoryCallback303ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieSessionId,
			Value:    session.ID.String(),
			Path:     "/api",
			Expires:  timex.Now().Add(sessionValidity),
			HttpOnly: true,
			Secure:   true,
			Domain:   strings.TrimPrefix(s.host, "https://"),
			SameSite: http.SameSiteLaxMode,
		}).String(),
		Location: s.host + "/",
	}
	return HandleDirectoryCallback303Response{Headers: headers}, nil
}

func (s Server) LogoutUser(ctx context.Context, req LogoutUserRequestObject) (LogoutUserResponseObject, error) {
	sessionID := ctx.Value(CtxKeySessionID).(string)
	_ = s.service.deleteSession(ctx, sessionID)

	headers := LogoutUser303ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieSessionId,
			Path:     "/api",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			Domain:   strings.TrimPrefix(s.host, "https://"),
			SameSite: http.SameSiteStrictMode,
		}).String(),
		Location: s.host + "/",
	}
	return LogoutUser303Response{Headers: headers}, nil
}

func (s Server) GetCurrentUser(ctx context.Context, req GetCurrentUserRequestObject) (GetCurrentUserResponseObject, error) {
	sessionID := ctx.Value(CtxKeySessionID).(string)
	session, err := s.service.session(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	resp := UserResponse{
		Data: struct {
			Organizations []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"organizations"`
			Username string `json:"username"`
		}{
			Organizations: []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{},
			Username: session.Username,
		},
	}
	for orgID, org := range session.Organizations {
		resp.Data.Organizations = append(resp.Data.Organizations, struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   orgID,
			Name: org.Name,
		})
	}
	return GetCurrentUser200JSONResponse(resp), nil
}

func (s Server) GetMockUsers(ctx context.Context, req GetMockUsersRequestObject) (GetMockUsersResponseObject, error) {
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	us, err := s.userService.Users(ctx, req.OrgID, pag)
	if err != nil {
		return nil, err
	}

	resp := MockUsersResponse{
		Data: []struct {
			Cpf      string `json:"cpf"`
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		}{},
		Meta:  api.NewPaginatedMeta(us),
		Links: api.NewPaginatedLinks(s.host+"/orgs/"+req.OrgID+"/users", us),
	}
	for _, u := range us.Records {
		resp.Data = append(resp.Data, struct {
			Cpf      string `json:"cpf"`
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		}{
			ID:       u.ID.String(),
			Username: u.Username,
			Cpf:      u.CPF,
			Name:     u.Name,
		})
	}
	return GetMockUsers200JSONResponse(resp), nil
}

func (s Server) CreateMockUser(ctx context.Context, req CreateMockUserRequestObject) (CreateMockUserResponseObject, error) {
	u := &user.User{
		Username: req.Body.Data.Username,
		Name:     req.Body.Data.Name,
		CPF:      req.Body.Data.Cpf,
		OrgID:    req.OrgID,
	}
	if err := s.userService.Save(ctx, u); err != nil {
		return nil, err
	}

	resp := MockUserResponse{
		Data: struct {
			Cpf      string  `json:"cpf"`
			ID       string  `json:"id"`
			Name     string  `json:"name"`
			Password *string `json:"password,omitempty"`
			Username string  `json:"username"`
		}{
			Cpf:      u.CPF,
			ID:       u.ID.String(),
			Name:     u.Name,
			Username: u.Name,
		},
	}
	return CreateMockUser201JSONResponse(resp), nil
}

func (s Server) UpdateMockUser(ctx context.Context, req UpdateMockUserRequestObject) (UpdateMockUserResponseObject, error) {
	u := &user.User{
		ID:       uuid.MustParse(req.UserID),
		Username: req.Body.Data.Username,
		Name:     req.Body.Data.Name,
		CPF:      req.Body.Data.Cpf,
		OrgID:    req.OrgID,
	}
	if err := s.userService.Save(ctx, u); err != nil {
		return nil, err
	}

	resp := MockUserResponse{
		Data: struct {
			Cpf      string  `json:"cpf"`
			ID       string  `json:"id"`
			Name     string  `json:"name"`
			Password *string `json:"password,omitempty"`
			Username string  `json:"username"`
		}{
			Cpf:      u.CPF,
			ID:       u.ID.String(),
			Name:     u.Name,
			Username: u.Name,
		},
	}
	return UpdateMockUser200JSONResponse(resp), nil
}

func (s Server) DeleteMockUser(ctx context.Context, req DeleteMockUserRequestObject) (DeleteMockUserResponseObject, error) {
	if err := s.userService.Delete(ctx, req.UserID, req.OrgID); err != nil {
		return nil, err
	}

	return DeleteMockUser204Response{}, nil
}

func (s Server) CreateAccount(ctx context.Context, req CreateAccountRequestObject) (CreateAccountResponseObject, error) {
	acc := &account.Account{
		Number:                      req.Body.Data.Number,
		Type:                        account.Type(req.Body.Data.Type),
		SubType:                     account.SubType(req.Body.Data.Subtype),
		AvailableAmount:             req.Body.Data.AvailableAmount,
		BlockedAmount:               req.Body.Data.BlockedAmount,
		AutomaticallyInvestedAmount: req.Body.Data.AutomaticallyInvestedAmount,
		OrgID:                       req.OrgID,
		UserID:                      req.UserID,
	}
	if err := s.accountService.Save(ctx, acc); err != nil {
		return nil, err
	}

	resp := AccountResponse{
		Data: AccountData{
			AccountID:                   acc.ID.String(),
			AutomaticallyInvestedAmount: acc.AutomaticallyInvestedAmount,
			AvailableAmount:             acc.AvailableAmount,
			BlockedAmount:               acc.BlockedAmount,
			BranchCode:                  account.DefaultBranch,
			CheckDigit:                  account.DefaultCheckDigit,
			CompeCode:                   account.DefaultCompeCode,
			Number:                      acc.Number,
			Subtype:                     string(acc.SubType),
			Type:                        string(acc.Type),
		},
	}

	return CreateAccount201JSONResponse(resp), nil
}

func (s Server) DeleteAccount(ctx context.Context, req DeleteAccountRequestObject) (DeleteAccountResponseObject, error) {
	if err := s.accountService.Delete(ctx, req.AccountID, req.OrgID); err != nil {
		return nil, err
	}
	return DeleteAccount204Response{}, nil
}

func (s Server) GetAccounts(ctx context.Context, req GetAccountsRequestObject) (GetAccountsResponseObject, error) {
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	accs, err := s.accountService.Accounts(ctx, req.UserID, req.OrgID, pag)
	if err != nil {
		return nil, err
	}

	resp := AccountsResponse{
		Data:  []AccountData{},
		Meta:  api.NewPaginatedMeta(accs),
		Links: api.NewPaginatedLinks(s.host+"/orgs/"+req.OrgID+"/users/"+req.UserID+"/accounts", accs),
	}
	for _, acc := range accs.Records {
		resp.Data = append(resp.Data, AccountData{
			AccountID:                   acc.ID.String(),
			AutomaticallyInvestedAmount: acc.AutomaticallyInvestedAmount,
			AvailableAmount:             acc.AvailableAmount,
			BlockedAmount:               acc.BlockedAmount,
			BranchCode:                  account.DefaultBranch,
			CheckDigit:                  account.DefaultCheckDigit,
			CompeCode:                   account.DefaultCompeCode,
			Number:                      acc.Number,
			Subtype:                     string(acc.SubType),
			Type:                        string(acc.Type),
		})
	}

	return GetAccounts200JSONResponse(resp), nil
}

func (s Server) GetConsents(ctx context.Context, req GetConsentsRequestObject) (GetConsentsResponseObject, error) {
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	cs, err := s.consentService.Consents(ctx, req.UserID, req.OrgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ConsentsResponse{
		Data: []struct {
			ClientID             string          `json:"clientId"`
			ConsentID            string          `json:"consentId"`
			CreationDateTime     timex.DateTime  `json:"creationDateTime"`
			ExpirationDateTime   *timex.DateTime `json:"expirationDateTime,omitempty"`
			Permissions          []string        `json:"permissions"`
			RejectedBy           *string         `json:"rejectedBy,omitempty"`
			RejectionReason      *string         `json:"rejectionReason,omitempty"`
			Status               string          `json:"status"`
			StatusUpdateDateTime timex.DateTime  `json:"statusUpdateDateTime"`
			UserID               string          `json:"userId"`
		}{},
		Meta:  api.NewPaginatedMeta(cs),
		Links: api.NewPaginatedLinks(s.host+"/orgs/"+req.OrgID+"/users/"+req.UserID+"/consents", cs),
	}
	for _, c := range cs.Records {
		data := struct {
			ClientID             string          `json:"clientId"`
			ConsentID            string          `json:"consentId"`
			CreationDateTime     timex.DateTime  `json:"creationDateTime"`
			ExpirationDateTime   *timex.DateTime `json:"expirationDateTime,omitempty"`
			Permissions          []string        `json:"permissions"`
			RejectedBy           *string         `json:"rejectedBy,omitempty"`
			RejectionReason      *string         `json:"rejectionReason,omitempty"`
			Status               string          `json:"status"`
			StatusUpdateDateTime timex.DateTime  `json:"statusUpdateDateTime"`
			UserID               string          `json:"userId"`
		}{
			ClientID:             c.ClientID,
			ConsentID:            c.URN(),
			CreationDateTime:     timex.NewDateTime(c.CreatedAt),
			Status:               string(c.Status),
			StatusUpdateDateTime: timex.NewDateTime(c.StatusUpdatedAt),
			UserID:               c.UserID.String(),
		}
		perms := make([]string, len(c.Permissions))
		for i, p := range c.Permissions {
			perms[i] = string(p)
		}
		data.Permissions = perms

		if c.RejectedBy != "" {
			rejectedBy := string(c.RejectedBy)
			data.RejectedBy = &rejectedBy
			rejectionReason := string(c.RejectionReason)
			data.RejectionReason = &rejectionReason
		}

		if c.ExpiresAt != nil {
			exp := timex.NewDateTime(*c.ExpiresAt)
			data.ExpirationDateTime = &exp
		}
		resp.Data = append(resp.Data, data)
	}
	return GetConsents200JSONResponse(resp), nil
}
