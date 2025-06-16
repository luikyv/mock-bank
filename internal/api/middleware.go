package api

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/google/uuid"
	netmiddleware "github.com/oapi-codegen/nethttp-middleware"
)

type Options struct {
	ErrorPagination bool
}

func FAPIIDMiddleware(opts *Options) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &Options{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			interactionID := r.Header.Get(HeaderXFAPIInteractionID)
			if _, err := uuid.Parse(interactionID); err != nil {
				w.Header().Add(HeaderXFAPIInteractionID, uuid.NewString())
				WriteError(w, r, NewError("PARAMETRO_INVALIDO", http.StatusBadRequest, "The fapi interaction id is missing or invalid").Pagination(opts.ErrorPagination))
				return
			}

			// Return the same interaction ID in the response.
			w.Header().Set(HeaderXFAPIInteractionID, interactionID)
			next.ServeHTTP(w, r)
		})
	}
}

func SwaggerMiddleware(getSwagger func() (*openapi3.T, error), errCode string) func(http.Handler) http.Handler {
	spec, err := getSwagger()
	if err != nil {
		panic(err)
	}
	return netmiddleware.OapiRequestValidatorWithOptions(spec, &netmiddleware.Options{
		DoNotValidateServers: true,
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
		ErrorHandlerWithOpts: func(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts netmiddleware.ErrorHandlerOpts) {
			WriteError(w, r, NewError(errCode, http.StatusUnprocessableEntity, err.Error()))
		},
	})
}
