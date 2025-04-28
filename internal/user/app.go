package user

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/api/middleware"
	"github.com/luiky/mock-bank/internal/auth"
	"github.com/luiky/mock-bank/internal/page"
)

var (
	errBadRequest = api.NewError("INVALID_REQUEST", http.StatusBadRequest, "invalid request")
)

type AppServer struct {
	host        string
	service     Service
	authService auth.Service
}

func NewAppServer(host string, service Service, authService auth.Service) AppServer {
	return AppServer{
		host:        host,
		service:     service,
		authService: authService,
	}
}

func (s AppServer) Register(mux *http.ServeMux) {
	appMux := http.NewServeMux()

	handler := s.createHandler()
	appMux.Handle("POST /app/users", handler)

	handler = s.usersHandler()
	appMux.Handle("GET /app/users", handler)

	handler = auth.Middleware(appMux, s.authService)
	handler = middleware.Meta(handler, s.host)
	mux.Handle("/app/users", handler)
}

func (s AppServer) createHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.Context().Value(api.CtxKeyOrgID).(string)

		var req userRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		user := req.toUser(orgID)
		if err := s.service.Save(r.Context(), user); err != nil {
			writeAppError(w, err)
			return
		}

		api.WriteJSON(w, toResponse(user), http.StatusCreated)
	})
}

func (s AppServer) usersHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.Context().Value(api.CtxKeyOrgID).(string)
		reqURL := r.Context().Value(api.CtxKeyRequestURL).(string)
		pag, err := api.NewPagination(r)
		if err != nil {
			writeAppError(w, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, err.Error()))
			return
		}

		us, err := s.service.users(r.Context(), orgID, pag)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := toUsersResponse(us, reqURL)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

type userRequest struct {
	Username string `json:"username"`
	CPF      string `json:"cpf"`
}

func (req userRequest) toUser(orgID string) User {
	return User{
		ID:       uuid.NewString(),
		Username: req.Username,
		CPF:      req.CPF,
		OrgID:    orgID,
	}
}

type userResponse struct {
	Username string `json:"username"`
	CPF      string `json:"cpf"`
}

func toResponse(u User) userResponse {
	return userResponse{
		Username: u.Username,
		CPF:      u.CPF,
	}
}

type usersResponse struct {
	Users []userResponse `json:"users"`
	Meta  api.Meta       `json:"meta"`
	Links api.Links      `json:"links"`
}

func toUsersResponse(us page.Page[User], reqURL string) usersResponse {
	resp := usersResponse{
		Meta:  api.NewPaginatedMeta(us),
		Links: api.NewPaginatedLinks(reqURL, us),
	}

	for _, u := range us.Records {
		resp.Users = append(resp.Users, toResponse(u))
	}

	return resp
}

func writeAppError(w http.ResponseWriter, err error) {
	api.WriteError(w, errBadRequest)
}
