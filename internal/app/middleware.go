package app

import (
	"context"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
)

func authMiddleware(next http.Handler, service Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie(cookieSessionId)
		if err != nil {
			writeError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found"))
			return
		}

		session, err := service.session(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, err)
			return
		}

		orgID := r.PathValue("org_id")
		if orgID == "" {
			api.WriteError(w, api.NewError("MISSING_ORG_ID", http.StatusBadRequest, "missing org id"))
			return
		}

		if _, ok := session.Organizations[orgID]; !ok {
			api.WriteError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid org id"))
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyOrgID, orgID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func metaMiddleware(next http.Handler, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyRequestURL, host+r.URL.RequestURI())
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
