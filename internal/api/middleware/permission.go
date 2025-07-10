package middleware

import (
	"log/slog"
	"net/http"

	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/consent"
)

// Permission creates a middleware that validates phase 2 consent permissions for the request.
// It checks if the consent is active, authorized, and has the required permissions.
// The consent ID is extracted from the scopes and added to the request context.
func Permission(consentService consent.Service, permissions ...consent.Permission) func(http.Handler) http.Handler {
	return PermissionWithOptions(consentService, nil, permissions...)
}

func PermissionWithOptions(consentService consent.Service, opts *Options, permissions ...consent.Permission) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &Options{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			id := ctx.Value(api.CtxKeyConsentID).(string)
			orgID := ctx.Value(api.CtxKeyOrgID).(string)

			c, err := consentService.Consent(ctx, id, orgID)
			if err != nil {
				slog.DebugContext(ctx, "could not find consent", "consent_id", id, "error", err)
				api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token").Pagination(opts.ErrorPagination))
				return
			}

			if c.Status != consent.StatusAuthorized {
				slog.DebugContext(ctx, "the consent is not authorized", "consent_id", id, "status", c.Status)
				api.WriteError(w, r, api.NewError("INVALID_STATUS", http.StatusUnauthorized, "the consent is not authorized").Pagination(opts.ErrorPagination))
				return
			}

			if !c.HasPermissions(permissions) {
				slog.DebugContext(ctx, "the consent doesn't have the required permissions", "consent_id", id)
				api.WriteError(w, r, api.NewError("INVALID_STATUS", http.StatusForbidden, "the consent is missing permissions").Pagination(opts.ErrorPagination))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
