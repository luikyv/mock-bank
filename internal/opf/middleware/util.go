package middleware

import (
	"context"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

type Options struct {
	ErrorPagination bool
}

func Meta(host string) strictnethttp.StrictHTTPMiddlewareFunc {
	return func(next strictnethttp.StrictHTTPHandlerFunc, operationID string) strictnethttp.StrictHTTPHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (response any, err error) {
			ctx = context.WithValue(ctx, api.CtxKeyRequestURL, host+r.URL.RequestURI())
			return next(ctx, w, r, req)
		}
	}
}

// func Meta(next http.Handler, host string) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		ctx := r.Context()
// 		ctx = context.WithValue(ctx, api.CtxKeyRequestURL, host+r.URL.RequestURI())
// 		r = r.WithContext(ctx)

// 		next.ServeHTTP(w, r)
// 	})
// }
