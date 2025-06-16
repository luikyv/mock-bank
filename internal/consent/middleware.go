package consent

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
)

func PermissionMiddleware(consentService Service, permissions ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes := r.Context().Value(api.CtxKeyScopes).(string)
			orgID := r.Context().Value(api.CtxKeyOrgID).(string)

			id, _ := IDFromScopes(scopes)
			c, err := consentService.Consent(r.Context(), id, orgID)
			if err != nil {
				slog.DebugContext(r.Context(), "the token is not active")
				api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token"))
				return
			}

			if !c.IsAuthorized() {
				slog.DebugContext(r.Context(), "the consent is not authorized")
				api.WriteError(w, r, api.NewError("INVALID_STATUS", http.StatusUnauthorized, "the consent is not authorized"))
				return
			}

			if !c.HasPermissions(permissions) {
				slog.DebugContext(r.Context(), "the consent doesn't have the required permissions")
				api.WriteError(w, r, api.NewError("INVALID_STATUS", http.StatusForbidden, "the consent is missing permissions"))
			}

			r = r.WithContext(context.WithValue(r.Context(), api.CtxKeyConsentID, id))
			next.ServeHTTP(w, r)
		})
	}
}
