package app

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/session"
)

func authSessionMiddleware(service session.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return authSessionMiddlewareHandler(next, service)
	}
}

func authSessionMiddlewareHandler(next http.Handler, service session.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/directory/auth-url" {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found"))
			return
		}

		session, err := service.Session(r.Context(), cookie.Value)
		if err != nil {
			api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found"))
			return
		}
		ctx = context.WithValue(ctx, api.CtxKeySessionID, session.ID.String())

		orgID := r.PathValue("orgId")
		if orgID != "" {
			if _, ok := session.Organizations[orgID]; !ok {
				api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid org id"))
				return
			}
			ctx = context.WithValue(ctx, api.CtxKeyOrgID, orgID)
		}

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func fapiIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interactionID := r.Header.Get(middleware.HeaderXFAPIInteractionID)
		// Verify if the interaction ID is valid, return a new value if not.
		if _, err := uuid.Parse(interactionID); err != nil {
			interactionID = uuid.NewString()
		}

		// Return the same interaction ID in the response.
		w.Header().Set(middleware.HeaderXFAPIInteractionID, interactionID)
		next.ServeHTTP(w, r)
	})
}
