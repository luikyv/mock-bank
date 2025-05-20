package app

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/session"
)

const (
	headerXInteractionID = "X-Interaction-ID"
)

func authSessionMiddleware(service session.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return authSessionMiddlewareHandler(next, service)
	}
}

func authSessionMiddlewareHandler(next http.Handler, service session.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/directory/") {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		cookie, err := r.Cookie(cookieSessionId)
		if err != nil {
			api.WriteError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found"))
			return
		}

		session, err := service.Session(r.Context(), cookie.Value)
		if err != nil {
			api.WriteError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found"))
			return
		}
		ctx = context.WithValue(ctx, api.CtxKeySessionID, session.ID.String())

		orgID := r.PathValue("orgId")
		if orgID != "" {
			if _, ok := session.Organizations[orgID]; !ok {
				api.WriteError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid org id"))
				return
			}
			ctx = context.WithValue(ctx, api.CtxKeyOrgID, orgID)
		}

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func interactionIDHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interactionID := r.Header.Get(headerXInteractionID)
		if _, err := uuid.Parse(interactionID); err != nil {
			interactionID = uuid.NewString()
		}

		// Return the same interaction ID in the response.
		w.Header().Set(headerXInteractionID, interactionID)

		ctx := context.WithValue(r.Context(), api.CtxKeyInteractionID, interactionID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func interactionIDMiddleware(next http.Handler) http.Handler {
	return interactionIDHandler(next)
}
