package user

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
)

type AppServer struct {
	service Service
}

func (s AppServer) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("POST /users", s.createHandler())
}

func (s AppServer) createHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req userRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		user := req.toUser()
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
		pag, err := api.NewPagination(r)
		if err != nil {
			writeAppError(w, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, err.Error()))
			return
		}

		users, err := s.service.users(r.Context(), orgID, pag)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := make([]userResponse, len(users))
		for i, user := range users {
			resp[i] = toResponse(user)
		}

		api.WriteJSON(w, resp, http.StatusOK)
	})
}

type userRequest struct {
	Username string `json:"username"`
	CPF      string `json:"cpf"`
}

func (req userRequest) toUser() User {
	return User{
		Username: req.Username,
		CPF:      req.CPF,
		OrgID:    uuid.NewString(),
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

func writeAppError(w http.ResponseWriter, err error) {
	api.WriteError(w, errBadRequest)
}
