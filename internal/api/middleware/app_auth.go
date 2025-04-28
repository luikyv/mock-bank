package middleware

import (
	"context"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
)

func AppAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.Header.Get(api.HeaderOrgID)
		if orgID == "" {
			api.WriteError(w, api.NewError("MISSING_ORG_ID", http.StatusBadRequest, "missing org id"))
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyOrgID, orgID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
