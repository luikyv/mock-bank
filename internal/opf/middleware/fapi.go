package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

const headerXFAPIInteractionID = "X-FAPI-Interaction-ID"

func FAPIID(optsMap map[string]Options) strictnethttp.StrictHTTPMiddlewareFunc {
	return func(next strictnethttp.StrictHTTPHandlerFunc, operationID string) strictnethttp.StrictHTTPHandlerFunc {
		opts := optsMap[operationID]
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (response any, err error) {
			interactionID := r.Header.Get(headerXFAPIInteractionID)
			// Verify if the interaction ID is valid, return a new value if not.
			if _, err := uuid.Parse(interactionID); err != nil {
				w.Header().Add(headerXFAPIInteractionID, uuid.NewString())
				return nil, api.NewError("INVALID_INTERACTION_ID", http.StatusBadRequest, "The fapi interaction id is missing or invalid").Pagination(opts.ErrorPagination)
			}

			// Return the same interaction ID in the response.
			w.Header().Add(headerXFAPIInteractionID, interactionID)

			ctx = context.WithValue(ctx, api.CtxKeyInteractionID, interactionID)
			return next(ctx, w, r, req)
		}
	}
}
