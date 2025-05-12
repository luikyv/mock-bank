package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/user"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
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

	handler := Handler(NewStrictHandler(s, []StrictMiddlewareFunc{
		metaMiddleware(s.host),
		authMiddleware(s.service),
	}))

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{s.host},
		AllowCredentials: true,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodDelete,
		},
	})
	handler = c.Handler(handler)
	mux.Handle("/api/", handler)
}

func writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSessionNotFound) {
		api.WriteError(w, api.NewError("UNAUTHORIZED", http.StatusUnauthorized, err.Error()))
		return
	}

	if errors.Is(err, user.ErrAlreadyExists) {
		api.WriteError(w, api.NewError("USER_ALREADY_EXISTS", http.StatusBadRequest, err.Error()))
		return
	}

	api.WriteError(w, err)
}

func (s Server) GetDirectoryAuthURL(ctx context.Context, request GetDirectoryAuthURLRequestObject) (GetDirectoryAuthURLResponseObject, error) {
	authURL, err := s.directoryService.authURL(ctx)
	if err != nil {
		return nil, err
	}

	resp := AuthURLResponse{
		Data: struct {
			URL string `json:"url"`
		}{
			URL: authURL,
		},
	}
	return GetDirectoryAuthURL200JSONResponse(resp), nil
}

func (s Server) HandleDirectoryCallback(ctx context.Context, req HandleDirectoryCallbackRequestObject) (HandleDirectoryCallbackResponseObject, error) {
	// TODO: Validate nonce, exp, ...
	session, err := s.service.createSession(ctx, req.Params.IDToken)
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
			Domain:   s.host,
		}).String(),
		Location: s.host + "/",
	}
	return HandleDirectoryCallback303Response{Headers: headers}, nil
}

func (s Server) LogoutUser(ctx context.Context, req LogoutUserRequestObject) (LogoutUserResponseObject, error) {
	sessionID := ctx.Value(api.CtxKeySessionID).(string)
	_ = s.service.deleteSession(ctx, sessionID)

	headers := LogoutUser303ResponseHeaders{
		SetCookie: (&http.Cookie{
			Name:     cookieSessionId,
			Path:     "/api",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
		}).String(),
		Location: s.host + "/",
	}
	return LogoutUser303Response{Headers: headers}, nil
}

func (s Server) GetCurrentUser(ctx context.Context, req GetCurrentUserRequestObject) (GetCurrentUserResponseObject, error) {
	sessionID := ctx.Value(api.CtxKeySessionID).(string)
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
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
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
		Links: api.NewPaginatedLinks(reqURL, us),
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

func (s Server) DeleteMockUser(ctx context.Context, req DeleteMockUserRequestObject) (DeleteMockUserResponseObject, error) {
	if err := s.userService.Delete(ctx, req.UserID, req.OrgID); err != nil {
		return nil, err
	}

	return DeleteMockUser204Response{}, nil
}

func (s Server) GetAccounts(ctx context.Context, req GetAccountsRequestObject) (GetAccountsResponseObject, error) {
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	accs, err := s.accountService.Accounts(ctx, req.UserID, req.OrgID, pag)
	if err != nil {
		return nil, err
	}

	resp := AccountsResponse{
		Data: []struct {
			AccountID  string  `json:"accountId"`
			BranchCode *string `json:"branchCode,omitempty"`
			CheckDigit string  `json:"checkDigit"`
			Number     string  `json:"number"`
			Type       string  `json:"type"`
		}{},
		Meta:  api.NewPaginatedMeta(accs),
		Links: api.NewPaginatedLinks(reqURL, accs),
	}
	for _, acc := range accs.Records {
		branchCode := account.DefaultBranch
		resp.Data = append(resp.Data, struct {
			AccountID  string  `json:"accountId"`
			BranchCode *string `json:"branchCode,omitempty"`
			CheckDigit string  `json:"checkDigit"`
			Number     string  `json:"number"`
			Type       string  `json:"type"`
		}{
			AccountID:  acc.ID,
			BranchCode: &branchCode,
			CheckDigit: account.DefaultCheckDigit,
			Number:     acc.Number,
			Type:       string(acc.Type),
		})
	}

	return GetAccounts200JSONResponse(resp), nil
}

func (s Server) GetConsents(ctx context.Context, req GetConsentsRequestObject) (GetConsentsResponseObject, error) {
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
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
		Links: api.NewPaginatedLinks(reqURL, cs),
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
