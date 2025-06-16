package api

import (
	"net/http"

	"github.com/google/uuid"
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
