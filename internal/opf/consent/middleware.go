package consent

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

type PermissionOptions struct {
	Permissions     []Permission
	ErrorPagination bool
}

func PermissionMiddleware(optsMap map[string]PermissionOptions, consentService Service) strictnethttp.StrictHTTPMiddlewareFunc {
	return func(next strictnethttp.StrictHTTPHandlerFunc, operationID string) strictnethttp.StrictHTTPHandlerFunc {
		opts := optsMap[operationID]
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (res any, err error) {
			scopes := ctx.Value(api.CtxKeyScopes).(string)
			orgID := ctx.Value(api.CtxKeyOrgID).(string)

			id, _ := ID(scopes)
			consent, err := consentService.Consent(ctx, id, orgID)
			if err != nil {
				slog.DebugContext(r.Context(), "the token is not active")
				return nil, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token").Pagination(opts.ErrorPagination)
			}

			if !consent.IsAuthorized() {
				slog.DebugContext(r.Context(), "the consent is not authorized")
				return nil, api.NewError("INVALID_STATUS", http.StatusUnauthorized, "the consent is not authorized").Pagination(opts.ErrorPagination)
			}

			if !consent.HasPermissions(opts.Permissions) {
				slog.DebugContext(r.Context(), "the consent doesn't have the required permissions")
				return nil, api.NewError("INVALID_STATUS", http.StatusForbidden, "the consent is missing permissions").Pagination(opts.ErrorPagination)
			}

			ctx = context.WithValue(ctx, api.CtxKeyConsentID, id)
			return next(ctx, w, r, req)
		}
	}
}
