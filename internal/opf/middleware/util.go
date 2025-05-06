package middleware

import (
	"context"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
)

type Options struct {
	ErrorPagination bool
}

func Meta(next http.Handler, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyRequestURL, host+r.URL.RequestURI())
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
