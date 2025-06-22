package idempotency

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"

	"github.com/luikyv/mock-bank/internal/api"
)

const headerIdempotencyID = "X-Idempotency-Key"

// Middleware ensures that requests with the same idempotency ID
// are not processed multiple times, returning a cached response if available.
func Middleware(service Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			idempotencyID := r.Header.Get(headerIdempotencyID)
			if idempotencyID == "" {
				api.WriteError(w, r, api.NewError("ERRO_IDEMPOTENCIA", http.StatusUnprocessableEntity, "missing idempotency key header"))
				return
			}

			// Read and cache request body for comparison or forwarding.
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				api.WriteError(w, r, api.NewError("ERRO_IDEMPOTENCIA", http.StatusBadRequest, "unable to read request body"))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			rec, err := service.Response(r.Context(), idempotencyID)
			if err == nil {
				// Validate if the current request body matches the stored one.
				if body := base64.RawStdEncoding.EncodeToString(bodyBytes); body != rec.Request {
					slog.DebugContext(r.Context(), "mismatched idempotent request payload", "id", rec.ID, "got", body, "expected", rec.Request)
					api.WriteError(w, r, api.NewError("ERRO_IDEMPOTENCIA", http.StatusUnprocessableEntity, "request payload does not match previous idempotent request"))
					return
				}

				slog.InfoContext(r.Context(), "return cached idempotency response")
				writeIdempotencyResp(w, r, rec)
				return
			}

			if !errors.Is(err, ErrNotFound) {
				api.WriteError(w, r, api.NewError("ERRO_IDEMPOTENCIA", http.StatusUnprocessableEntity, err.Error()))
				return
			}

			// No previous record, continue and capture response.
			recorder := &responseRecorder{ResponseWriter: w, Body: &bytes.Buffer{}, StatusCode: http.StatusOK}
			next.ServeHTTP(recorder, r)

			// Only successful responses are stored.
			if !slices.Contains([]int{http.StatusOK, http.StatusCreated, http.StatusAccepted}, recorder.StatusCode) {
				return
			}

			err = service.Create(r.Context(), &Record{
				ID:         idempotencyID,
				Request:    base64.RawStdEncoding.EncodeToString(bodyBytes),
				Response:   recorder.Body.String(),
				StatusCode: recorder.StatusCode,
			})
			if err != nil {
				slog.ErrorContext(r.Context(), "failed to store idempotent response", "error", err)
			}
		})
	}

}

func writeIdempotencyResp(w http.ResponseWriter, r *http.Request, rec *Record) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rec.StatusCode)

	if len(rec.Response) == 0 {
		slog.DebugContext(r.Context(), "idempotency record has no response body", "id", rec.ID)
		return
	}

	resp, _ := base64.RawStdEncoding.DecodeString(rec.Response)
	if _, err := w.Write(resp); err != nil {
		slog.ErrorContext(r.Context(), "failed to write cached idempotent response body", "error", err)
	}
}

type responseRecorder struct {
	http.ResponseWriter
	Body       *bytes.Buffer
	StatusCode int
}

func (rr *responseRecorder) WriteHeader(statusCode int) {
	rr.StatusCode = statusCode
	rr.ResponseWriter.WriteHeader(statusCode)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	rr.Body.Write(b)
	return rr.ResponseWriter.Write(b)
}
