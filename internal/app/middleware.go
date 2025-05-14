package app

import (
	"context"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

func authMiddleware(service Service) strictnethttp.StrictHTTPMiddlewareFunc {
	return func(next strictnethttp.StrictHTTPHandlerFunc, operationID string) strictnethttp.StrictHTTPHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (response interface{}, err error) {
			// TODO: Review this.
			orgID := r.PathValue("org_id")
			if orgID == "" {
				return next(ctx, w, r, req)
			}

			cookie, err := r.Cookie(cookieSessionId)
			if err != nil {
				return nil, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "session not found")
			}

			session, err := service.session(r.Context(), cookie.Value)
			if err != nil {
				return nil, err
			}

			if _, ok := session.Organizations[orgID]; !ok {
				return nil, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid org id")
			}

			ctx = context.WithValue(ctx, api.CtxKeyOrgID, orgID)
			ctx = context.WithValue(ctx, api.CtxKeySessionID, session.ID)
			return next(ctx, w, r, req)
		}
	}
}

func metaMiddleware(host string) strictnethttp.StrictHTTPMiddlewareFunc {
	return func(next strictnethttp.StrictHTTPHandlerFunc, operationID string) strictnethttp.StrictHTTPHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (response any, err error) {
			ctx = context.WithValue(ctx, api.CtxKeyRequestURL, host+r.URL.RequestURI())
			return next(ctx, w, r, req)
		}
	}
}
