package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
)

const (
	HeaderXFAPIInteractionID = "X-FAPI-Interaction-ID"
)

func FAPIID(next http.Handler, opts *Options) http.Handler {
	if opts == nil {
		opts = &Options{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interactionID := r.Header.Get(HeaderXFAPIInteractionID)
		// Verify if the interaction ID is valid, return a new value if not.
		if _, err := uuid.Parse(interactionID); err != nil {
			w.Header().Add(HeaderXFAPIInteractionID, uuid.NewString())
			api.WriteJSON(w, api.NewError("INVALID_INTERACTION_ID", http.StatusBadRequest, "The fapi interaction id is missing or invalid").Pagination(opts.ErrorPagination), http.StatusBadRequest)
			return
		}

		// Return the same interaction ID in the response.
		w.Header().Set(HeaderXFAPIInteractionID, interactionID)
		next.ServeHTTP(w, r)
	})
}

func FAPIIDFunc(opts *Options) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &Options{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			interactionID := r.Header.Get(HeaderXFAPIInteractionID)
			// Verify if the interaction ID is valid, return a new value if not.
			if _, err := uuid.Parse(interactionID); err != nil {
				w.Header().Add(HeaderXFAPIInteractionID, uuid.NewString())
				api.WriteJSON(w, api.NewError("INVALID_INTERACTION_ID", http.StatusBadRequest, "The fapi interaction id is missing or invalid").Pagination(opts.ErrorPagination), http.StatusBadRequest)
				return
			}

			// Return the same interaction ID in the response.
			w.Header().Set(HeaderXFAPIInteractionID, interactionID)
			next.ServeHTTP(w, r)
		})

	}
}
