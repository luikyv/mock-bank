package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/api/middleware"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/rs/cors"
)

type Server struct {
	host             string
	frontHost        string
	service          Service
	directoryService DirectoryService
	userService      user.Service
	consentService   consent.Service
}

func NewServer(
	host, frontHost string,
	service Service,
	directoryService DirectoryService,
	userService user.Service,
	consentService consent.Service,
) Server {
	return Server{
		host:             host,
		frontHost:        frontHost,
		service:          service,
		directoryService: directoryService,
		userService:      userService,
		consentService:   consentService,
	}
}

func (app Server) Register(mux *http.ServeMux) {
	appMux := http.NewServeMux()

	appMux.Handle("GET /app/orgs/{org_id}/users", app.mockUsersHandler())
	appMux.Handle("POST /app/orgs/{org_id}/users", app.createMockUserHandler())
	appMux.Handle("GET /app/orgs/{org_id}/users/{user_id}", app.mockUserHandler())
	appMux.Handle("DELETE /app/orgs/{org_id}/users/{user_id}", app.deleteMockUserHandler())

	appMux.Handle("GET /app/orgs/{org_id}/users/{user_id}/consents", app.consentsHandler())
	appHandler := middleware.Meta(appMux, app.host)
	appHandler = authMiddleware(appHandler, app.service)

	authMux := http.NewServeMux()
	authMux.Handle("GET /app/directory/auth-url", app.directoryAuthURLHandler())
	authMux.Handle("GET /app/directory/callback", app.directoryCallbackHandler())
	authMux.Handle("GET /app/me", app.userHandler())
	authMux.Handle("POST /app/logout", app.logoutHandler())
	authHandler := middleware.Meta(authMux, app.host)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{app.frontHost},
		AllowCredentials: true,
		AllowedMethods:   []string{"HEAD", "GET", "POST", "DELETE"},
	})
	mux.Handle("/app/orgs/{org_id}/", c.Handler(appHandler))
	mux.Handle("/app/", c.Handler(authHandler))
}

func (app Server) directoryAuthURLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authURL, err := app.directoryService.authURL(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}

		resp := toDirectoryAuthURLResponse(authURL)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

func (app Server) directoryCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Validate nonce, exp, ...
		idTkn := r.URL.Query().Get("id_token")
		if idTkn == "" {
			writeError(w, api.NewError("BAD_REQUEST", http.StatusBadRequest, "the id token is missing"))
			return
		}

		session, err := app.service.createSession(r.Context(), idTkn)
		if err != nil {
			writeError(w, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieSessionId,
			Value:    session.ID,
			Path:     "/app",
			Expires:  timex.Now().Add(sessionValidity),
			HttpOnly: true,
			Secure:   true,
			Domain:   ".mockbank.local", // TODO: Fix this.
		})
		http.Redirect(w, r, app.frontHost+"/", http.StatusSeeOther)
	})
}

func (app Server) userHandler() http.Handler {
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

func (app Server) logoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(cookieSessionId); err == nil {
			_ = app.service.deleteSession(r.Context(), cookie.Value)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieSessionId,
			Path:     "/app",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
		})
		http.Redirect(w, r, app.host+"/login", http.StatusSeeOther)
	})
}

func (s Server) createMockUserHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		reqURL := r.Context().Value(api.CtxKeyRequestURL).(string)

		var req mockUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, api.NewError("BAD_REQUEST", http.StatusBadRequest, "could not parse body"))
			return
		}

		u := req.toMockUser(orgID)
		if err := s.userService.Save(r.Context(), u); err != nil {
			writeError(w, err)
			return
		}

		api.WriteJSON(w, toMockUserResponse(u, reqURL), http.StatusCreated)
	})
}

func (s Server) mockUsersHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		reqURL := r.Context().Value(api.CtxKeyRequestURL).(string)
		pag, err := api.NewPagination(r)
		if err != nil {
			writeError(w, err)
			return
		}

		users, err := s.userService.Users(r.Context(), orgID, pag)
		if err != nil {
			writeError(w, err)
			return
		}

		resp := toMockUsersResponse(users, reqURL)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

func (s Server) mockUserHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("user_id")
		orgID := r.PathValue("org_id")
		reqURL := r.Context().Value(api.CtxKeyRequestURL).(string)

		u, err := s.userService.User(r.Context(), userID, orgID)
		if err != nil {
			writeError(w, err)
			return
		}

		resp := toMockUserResponse(u, reqURL)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

func (s Server) deleteMockUserHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("user_id")
		orgID := r.PathValue("org_id")

		if err := s.userService.Delete(r.Context(), userID, orgID); err != nil {
			writeError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func (s Server) consentsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		userID := r.PathValue("user_id")
		pag, err := api.NewPagination(r)
		if err != nil {
			writeError(w, err)
			return
		}

		cs, err := s.consentService.Consents(r.Context(), userID, orgID, pag)
		if err != nil {
			writeError(w, err)
			return
		}

		resp := toConsentsResponse(cs, s.host)
		api.WriteJSON(w, resp, http.StatusOK)
	})
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
