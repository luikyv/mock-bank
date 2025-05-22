package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/directory"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/resource"
	"github.com/luiky/mock-bank/internal/session"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	netmiddleware "github.com/oapi-codegen/nethttp-middleware"
	"github.com/rs/cors"
)

const (
	cookieSessionId = "sessionId"
	cookieNonce     = "nonce"
	sessionValidity = 24 * time.Hour
	nonceValidity   = 15 * time.Minute
)

var _ StrictServerInterface = Server{}

type Server struct {
	host             string
	sessionService   session.Service
	directoryService directory.Service
	userService      user.Service
	consentService   consent.Service
	resourceService  resource.Service
	accountService   account.Service
}

func NewServer(
	host string,
	service session.Service,
	directoryService directory.Service,
	userService user.Service,
	consentService consent.Service,
	resourceService resource.Service,
	accountService account.Service,
) Server {
	return Server{
		host:             host,
		sessionService:   service,
		directoryService: directoryService,
		userService:      userService,
		consentService:   consentService,
		resourceService:  resourceService,
		accountService:   accountService,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {

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

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{s.host},
		AllowCredentials: true,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodDelete,
			http.MethodPut,
			http.MethodPatch,
		},
	})

	strictHandler := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeResponseError(w, err)
		},
	})

	handler := HandlerWithOptions(strictHandler, StdHTTPServerOptions{
		Middlewares: []MiddlewareFunc{
			swaggerMiddleware,
			fapiIDMiddleware,
			authSessionMiddleware(s.sessionService),
			func(next http.Handler) http.Handler {
				return c.Handler(next)
			},
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	})
	mux.Handle("/api/", handler)
}

func writeResponseError(w http.ResponseWriter, err error) {
	if errors.Is(err, session.ErrNotFound) {
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

	authURL, nonceHash, err := s.directoryService.AuthURL(ctx)
	if err != nil {
		return nil, err
	}

	headers := GetDirectoryAuthURL200ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieNonce,
			Value:    nonceHash,
			Path:     "/api/directory/callback",
			Expires:  timeutil.Now().Add(nonceValidity),
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
	session, err := s.sessionService.CreateSession(ctx, req.Params.IDToken, req.Params.Nonce)
	if err != nil {
		return nil, err
	}

	headers := HandleDirectoryCallback303ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieSessionId,
			Value:    session.ID.String(),
			Path:     "/api",
			Expires:  timeutil.Now().Add(sessionValidity),
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
	sessionID := ctx.Value(api.CtxKeySessionID).(string)
	_ = s.sessionService.DeleteSession(ctx, sessionID)

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
	sessionID := ctx.Value(api.CtxKeySessionID).(string)
	session, err := s.sessionService.Session(ctx, sessionID)
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
			Cpf         string  `json:"cpf"`
			Description *string `json:"description,omitempty"`
			ID          string  `json:"id"`
			Name        string  `json:"name"`
			Username    string  `json:"username"`
		}{},
		Meta:  api.NewPaginatedMeta(us),
		Links: api.NewPaginatedLinks(s.host+"/api/orgs/"+req.OrgID+"/users", us),
	}
	for _, u := range us.Records {
		data := struct {
			Cpf         string  `json:"cpf"`
			Description *string `json:"description,omitempty"`
			ID          string  `json:"id"`
			Name        string  `json:"name"`
			Username    string  `json:"username"`
		}{
			ID:       u.ID.String(),
			Username: u.Username,
			Cpf:      u.CPF,
			Name:     u.Name,
		}
		if u.Description != "" {
			data.Description = &u.Description
		}
		resp.Data = append(resp.Data, data)
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
	if req.Body.Data.Description != nil {
		u.Description = *req.Body.Data.Description
	}

	if err := s.userService.Save(ctx, u); err != nil {
		return nil, err
	}

	resp := MockUserResponse{
		Data: struct {
			Cpf         string  `json:"cpf"`
			Description *string `json:"description,omitempty"`
			ID          string  `json:"id"`
			Name        string  `json:"name"`
			Password    *string `json:"password,omitempty"`
			Username    string  `json:"username"`
		}{
			Cpf:      u.CPF,
			ID:       u.ID.String(),
			Name:     u.Name,
			Username: u.Name,
		},
	}
	if u.Description != "" {
		resp.Data.Description = &u.Description
	}
	return CreateMockUser201JSONResponse(resp), nil
}

func (s Server) UpdateMockUser(ctx context.Context, req UpdateMockUserRequestObject) (UpdateMockUserResponseObject, error) {
	u := &user.User{
		ID:       req.UserID,
		Username: req.Body.Data.Username,
		Name:     req.Body.Data.Name,
		CPF:      req.Body.Data.Cpf,
		OrgID:    req.OrgID,
	}
	if req.Body.Data.Description != nil {
		u.Description = *req.Body.Data.Description
	}
	if err := s.userService.Save(ctx, u); err != nil {
		return nil, err
	}

	resp := MockUserResponse{
		Data: struct {
			Cpf         string  `json:"cpf"`
			Description *string `json:"description,omitempty"`
			ID          string  `json:"id"`
			Name        string  `json:"name"`
			Password    *string `json:"password,omitempty"`
			Username    string  `json:"username"`
		}{
			Cpf:      u.CPF,
			ID:       u.ID.String(),
			Name:     u.Name,
			Username: u.Name,
		},
	}
	if u.Description != "" {
		resp.Data.Description = &u.Description
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

func (s Server) UpdateAccount(ctx context.Context, req UpdateAccountRequestObject) (UpdateAccountResponseObject, error) {
	acc := &account.Account{
		ID:                          req.AccountID,
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

	return UpdateAccount201JSONResponse(resp), nil
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
		Links: api.NewPaginatedLinks(s.host+"/api/orgs/"+req.OrgID+"/users/"+req.UserID.String()+"/accounts", accs),
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
			ClientID             string             `json:"clientId"`
			ConsentID            string             `json:"consentId"`
			CreationDateTime     timeutil.DateTime  `json:"creationDateTime"`
			ExpirationDateTime   *timeutil.DateTime `json:"expirationDateTime,omitempty"`
			Permissions          []string           `json:"permissions"`
			RejectedBy           *string            `json:"rejectedBy,omitempty"`
			RejectionReason      *string            `json:"rejectionReason,omitempty"`
			Status               string             `json:"status"`
			StatusUpdateDateTime timeutil.DateTime  `json:"statusUpdateDateTime"`
			UserID               string             `json:"userId"`
		}{},
		Meta:  api.NewPaginatedMeta(cs),
		Links: api.NewPaginatedLinks(s.host+"/api/orgs/"+req.OrgID+"/users/"+req.UserID.String()+"/consents", cs),
	}
	for _, c := range cs.Records {
		data := struct {
			ClientID             string             `json:"clientId"`
			ConsentID            string             `json:"consentId"`
			CreationDateTime     timeutil.DateTime  `json:"creationDateTime"`
			ExpirationDateTime   *timeutil.DateTime `json:"expirationDateTime,omitempty"`
			Permissions          []string           `json:"permissions"`
			RejectedBy           *string            `json:"rejectedBy,omitempty"`
			RejectionReason      *string            `json:"rejectionReason,omitempty"`
			Status               string             `json:"status"`
			StatusUpdateDateTime timeutil.DateTime  `json:"statusUpdateDateTime"`
			UserID               string             `json:"userId"`
		}{
			ClientID:             c.ClientID,
			ConsentID:            c.URN(),
			CreationDateTime:     timeutil.NewDateTime(c.CreatedAt),
			Status:               string(c.Status),
			StatusUpdateDateTime: timeutil.NewDateTime(c.StatusUpdatedAt),
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
			exp := timeutil.NewDateTime(*c.ExpiresAt)
			data.ExpirationDateTime = &exp
		}
		resp.Data = append(resp.Data, data)
	}
	return GetConsents200JSONResponse(resp), nil
}

func (s Server) GetResources(ctx context.Context, req GetResourcesRequestObject) (GetResourcesResponseObject, error) {
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	rs, err := s.resourceService.Resources(ctx, req.UserID, req.OrgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResourcesResponse{
		Data: []struct {
			ConsentID        string            `json:"consentId"`
			CreationDateTime timeutil.DateTime `json:"creationDateTime"`
			ResourceID       string            `json:"resourceId"`
			Status           ResourceStatus    `json:"status"`
			Type             ResourceType      `json:"type"`
		}{},
		Meta:  *api.NewPaginatedMeta(rs),
		Links: *api.NewPaginatedLinks(s.host+"/api/orgs/"+req.OrgID+"/users/"+req.UserID.String()+"/resources", rs),
	}

	for _, r := range rs.Records {
		resp.Data = append(resp.Data, struct {
			ConsentID        string            `json:"consentId"`
			CreationDateTime timeutil.DateTime `json:"creationDateTime"`
			ResourceID       string            `json:"resourceId"`
			Status           ResourceStatus    `json:"status"`
			Type             ResourceType      `json:"type"`
		}{
			ConsentID:        r.ConsentID,
			ResourceID:       r.ResourceID,
			Status:           ResourceStatus(r.Status),
			Type:             ResourceType(r.Type),
			CreationDateTime: timeutil.NewDateTime(r.CreatedAt),
		})
	}

	return GetResources200JSONResponse(resp), nil
}

func (s Server) PatchResourceStatus(ctx context.Context, req PatchResourceStatusRequestObject) (PatchResourceStatusResponseObject, error) {
	switch resource.Type(req.Params.Type) {
	case resource.TypeAccount:
		if err := s.accountService.UpdateConsent(ctx, req.ConsentID, uuid.MustParse(req.ResourceID), req.OrgID, resource.Status(req.Body.Data.Status)); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid resource type")
	}

	return PatchResourceStatus204Response{}, nil
}
