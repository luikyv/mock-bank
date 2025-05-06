package consent

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/middleware"
)

func PermissionMiddleware(next http.Handler, consentService Service, permissions []Permission, opts *middleware.Options) http.Handler {
	pagination := opts != nil && opts.ErrorPagination

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		scopes := ctx.Value(api.CtxKeyScopes).(string)
		orgID := ctx.Value(api.CtxKeyOrgID).(string)

		id, _ := ID(scopes)
		consent, err := consentService.Consent(ctx, id, orgID)
		if err != nil {
			slog.DebugContext(r.Context(), "the token is not active")
			err := api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token")
			if pagination {
				err = err.WithPagination()
			}
			api.WriteError(w, err)
			return
		}

		if !consent.IsAuthorized() {
			slog.DebugContext(r.Context(), "the consent is not authorized")
			err := api.NewError("INVALID_STATUS", http.StatusUnauthorized, "the consent is not authorized")
			if pagination {
				err = err.WithPagination()
			}
			api.WriteError(w, err)
			return
		}

		if !consent.HasPermissions(permissions) {
			slog.DebugContext(r.Context(), "the consent doesn't have the required permissions")
			err := api.NewError("INVALID_STATUS", http.StatusForbidden, "the consent is missing permissions")
			if pagination {
				err = err.WithPagination()
			}
			api.WriteError(w, err)
			return
		}

		ctx = context.WithValue(ctx, api.CtxKeyConsentID, id)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
