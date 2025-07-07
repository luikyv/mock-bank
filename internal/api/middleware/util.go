package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/oidc"
	netmiddleware "github.com/oapi-codegen/nethttp-middleware"
)

const (
	HeaderCustomerIPAddress  = "X-FAPI-Customer-IP-Address"
	HeaderCustomerUserAgent  = "X-Customer-User-Agent"
	HeaderXFAPIInteractionID = "X-FAPI-Interaction-ID"
)

type Options struct {
	ErrorPagination bool
}

func CertCN(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert, err := oidc.ClientCert(r)
		if err != nil {
			slog.ErrorContext(r.Context(), "could not get client certificate", "error", err)
			api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid certificate: could not get client certificate").Pagination(true))
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyCertCN, cert.Subject.CommonName)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func FAPIID() func(http.Handler) http.Handler {
	return FAPIIDWithOptions(nil)
}

func FAPIIDWithOptions(opts *Options) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &Options{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			interactionID := r.Header.Get(HeaderXFAPIInteractionID)
			if _, err := uuid.Parse(interactionID); err != nil {
				w.Header().Add(HeaderXFAPIInteractionID, uuid.NewString())
				api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusBadRequest, "The fapi interaction id is missing or invalid").Pagination(opts.ErrorPagination))
				return
			}

			// Return the same interaction ID in the response.
			w.Header().Set(HeaderXFAPIInteractionID, interactionID)
			next.ServeHTTP(w, r)
		})
	}
}

func Swagger(getSwagger func() (*openapi3.T, error), errCodeFunc func(error) string) (middleware func(http.Handler) http.Handler, version string) {
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
			api.WriteError(w, r, api.NewError(errCodeFunc(err), http.StatusUnprocessableEntity, err.Error()))
		},
	}), spec.Info.Version
}

func Version(v string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-V", v)
			next.ServeHTTP(w, r)
		})
	}
}
