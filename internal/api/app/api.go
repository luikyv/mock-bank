//go:generate oapi-codegen -config=./config.yml -package=app -o=./api_gen.go ./swagger.yml
package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/session"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
)

const (
	cookieSessionId = "sessionId"
	sessionValidity = 3 * time.Hour
)

var _ StrictServerInterface = Server{}

type Server struct {
	host            string
	sessionService  session.Service
	userService     user.Service
	consentService  consent.Service
	resourceService resource.Service
	accountService  account.Service
}

func NewServer(
	host string,
	service session.Service,
	userService user.Service,
	consentService consent.Service,
	resourceService resource.Service,
	accountService account.Service,
) Server {
	return Server{
		host:            host,
		sessionService:  service,
		userService:     userService,
		consentService:  consentService,
		resourceService: resourceService,
		accountService:  accountService,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {

	swaggerMiddleware, _ := api.SwaggerMiddleware(GetSwagger, func(err error) string { return "PARAMETRO_INVALIDO" })
	secureMiddleware := secure.New(secure.Options{
		STSSeconds:            31536000,
		STSIncludeSubdomains:  true,
		STSPreload:            true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'",
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

	handler := HandlerWithOptions(NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeResponseError(w, r, err)
		},
	}), StdHTTPServerOptions{
		Middlewares: []MiddlewareFunc{
			swaggerMiddleware,
			fapiIDMiddleware,
			authSessionMiddleware(s.sessionService),
			func(next http.Handler) http.Handler {
				return c.Handler(next)
			},
			func(next http.Handler) http.Handler {
				return secureMiddleware.Handler(next)
			},
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	})
	mux.Handle("/api/", handler)
}

func (s Server) GetDirectoryAuthURL(ctx context.Context, request GetDirectoryAuthURLRequestObject) (GetDirectoryAuthURLResponseObject, error) {
	session, authURL, err := s.sessionService.CreateSession(ctx)
	if err != nil {
		return nil, err
	}
	headers := GetDirectoryAuthURL200ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieSessionId,
			Value:    session.ID.String(),
			Path:     "/api",
			Expires:  timeutil.DateTimeNow().Add(sessionValidity).Time,
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
	sessionID := ctx.Value(api.CtxKeySessionID).(string)
	if err := s.sessionService.AuthorizeSession(ctx, sessionID, req.Params.Code); err != nil {
		return nil, err
	}

	headers := HandleDirectoryCallback303ResponseHeaders{
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
			ID:          u.ID.String(),
			Username:    u.Username,
			Cpf:         u.CPF,
			Name:        u.Name,
			Description: u.Description,
		}
		resp.Data = append(resp.Data, data)
	}
	return GetMockUsers200JSONResponse(resp), nil
}

func (s Server) CreateMockUser(ctx context.Context, req CreateMockUserRequestObject) (CreateMockUserResponseObject, error) {
	u := &user.User{
		Username:    req.Body.Data.Username,
		Name:        req.Body.Data.Name,
		CPF:         req.Body.Data.Cpf,
		Description: req.Body.Data.Description,
		OrgID:       req.OrgID,
	}

	if err := s.userService.Create(ctx, u); err != nil {
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
			Cpf:         u.CPF,
			ID:          u.ID.String(),
			Name:        u.Name,
			Username:    u.Name,
			Description: u.Description,
		},
	}
	return CreateMockUser201JSONResponse(resp), nil
}

func (s Server) UpdateMockUser(ctx context.Context, req UpdateMockUserRequestObject) (UpdateMockUserResponseObject, error) {
	u := &user.User{
		ID:          req.UserID,
		Username:    req.Body.Data.Username,
		Name:        req.Body.Data.Name,
		CPF:         req.Body.Data.Cpf,
		Description: req.Body.Data.Description,
		OrgID:       req.OrgID,
	}
	if err := s.userService.Update(ctx, u); err != nil {
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
			Cpf:         u.CPF,
			ID:          u.ID.String(),
			Name:        u.Name,
			Username:    u.Name,
			Description: u.Description,
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

func (s Server) BindUserToBusiness(ctx context.Context, req BindUserToBusinessRequestObject) (BindUserToBusinessResponseObject, error) {
	if err := s.userService.BindUserToBusiness(ctx, req.UserID, req.BusinessID, req.OrgID); err != nil {
		return nil, err
	}

	return BindUserToBusiness201Response{}, nil
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
	if err := s.accountService.Create(ctx, acc); err != nil {
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
	if err := s.accountService.Update(ctx, acc); err != nil {
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
	accs, err := s.accountService.Accounts(ctx, req.UserID.String(), req.OrgID, pag)
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
			CreationDateTime:     c.CreatedAt,
			Status:               string(c.Status),
			StatusUpdateDateTime: c.StatusUpdatedAt,
			ExpirationDateTime:   c.ExpiresAt,
			UserID:               c.OwnerID.String(),
		}
		perms := make([]string, len(c.Permissions))
		for i, p := range c.Permissions {
			perms[i] = string(p)
		}
		data.Permissions = perms

		// TODO: Make the rejection an object.
		if c.Rejection != nil {
			rejectedBy := string(c.Rejection.By)
			data.RejectedBy = &rejectedBy
			rejectionReason := string(c.Rejection.Reason)
			data.RejectionReason = &rejectionReason
		}

		resp.Data = append(resp.Data, data)
	}
	return GetConsents200JSONResponse(resp), nil
}

func (s Server) GetResources(ctx context.Context, req GetResourcesRequestObject) (GetResourcesResponseObject, error) {
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)

	rs, err := s.resourceService.Resources(ctx, req.OrgID, resource.Filter{UserID: req.UserID.String()}, pag)
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
			CreationDateTime: r.CreatedAt,
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

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, session.ErrNotFound) {
		api.WriteError(w, r, api.NewError("UNAUTHORIZED", http.StatusUnauthorized, err.Error()))
		return
	}

	if errors.Is(err, user.ErrAlreadyExists) {
		api.WriteError(w, r, api.NewError("USER_ALREADY_EXISTS", http.StatusBadRequest, err.Error()))
		return
	}

	if errors.Is(err, user.ErrInvalidOrgID) {
		api.WriteError(w, r, api.NewError("INVALID_ORG_ID", http.StatusBadRequest, err.Error()))
		return
	}

	if errors.Is(err, account.ErrAlreadyExists) {
		api.WriteError(w, r, api.NewError("ACCOUNT_ALREADY_EXISTS", http.StatusBadRequest, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}
