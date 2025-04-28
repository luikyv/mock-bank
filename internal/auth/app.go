package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/timex"
)

type AppServer struct {
	host    string
	service Service
}

func NewAppServer(host string, service Service) AppServer {
	return AppServer{
		host:    host,
		service: service,
	}
}

func (app AppServer) Register(mux *http.ServeMux) {
	mux.Handle("GET /app/callback", app.directoryCallbackHandler())
	mux.Handle("GET /app/me", app.userHandler())
	mux.Handle("GET /app/logout", app.logoutHandler())
}

func (app AppServer) directoryCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session := Session{
			ID:            uuid.NewString(),
			Organizations: map[string]Organization{},
		}
		if err := app.service.createSession(r.Context(), session); err != nil {
			writeError(w, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieSessionId,
			Value:    session.ID,
			Path:     "/app",
			Expires:  timex.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   false,
		})
		http.Redirect(w, r, app.host+"/home", http.StatusSeeOther)
	})
}

func (app AppServer) userHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieSessionId)
		if err != nil {
			writeError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found"))
			return
		}

		session, err := app.service.session(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, err)
			return
		}

		resp := toUserResponse(session)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

func (app AppServer) logoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(cookieSessionId); err == nil {
			_ = app.service.deleteSession(r.Context(), cookie.Value)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

type userResponse struct {
	Username      string                     `json:"username"`
	Organizations map[string]userOrgResponse `json:"organizations"`
}

type userOrgResponse struct {
	Name string `json:"name"`
}

func toUserResponse(s Session) userResponse {
	resp := userResponse{
		Username:      s.Username,
		Organizations: map[string]userOrgResponse{},
	}
	for orgID, org := range s.Organizations {
		resp.Organizations[orgID] = userOrgResponse(org)
	}

	return resp
}

func writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNotFound) {
		err := api.NewError("UNAUTHORIZED", http.StatusUnauthorized, err.Error())
		api.WriteError(w, err)
		return
	}

	api.WriteError(w, err)
}
