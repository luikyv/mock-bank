package consent

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf"
)

func PermissionMiddleware(next http.Handler, consentService Service, permissions ...Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes := r.Context().Value(opf.CtxKeyScopes).(string)
		orgID := r.Context().Value(opf.CtxKeyOrgID).(string)

		consentID, _ := IDFromScopes(scopes)
		consent, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.DebugContext(r.Context(), "the token is not active")
			api.WriteError(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token"))
			return
		}

		if !consent.IsAuthorized() {
			slog.DebugContext(r.Context(), "the consent is not authorized")
			api.WriteError(w, api.NewError("INVALID_STATUS", http.StatusUnauthorized, "the consent is not authorized"))
			return
		}

		if !consent.HasPermissions(permissions) {
			slog.DebugContext(r.Context(), "the consent doesn't have the required permissions")
			api.WriteError(w, api.NewError("INVALID_STATUS", http.StatusForbidden, "the consent is missing permissions"))
		}

		r = r.WithContext(context.WithValue(r.Context(), opf.CtxKeyConsentID, consentID))
		next.ServeHTTP(w, r)
	})
}
