package idempotency

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
)

const headerIdempotencyID = "X-Idempotency-Key"

// IdempotencyMiddleware ensures that requests with the same idempotency ID
// are not processed multiple times, returning a cached response if available.
func IdempotencyMiddleware(next http.Handler, service Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idempotencyID := r.Header.Get(headerIdempotencyID)
		if idempotencyID == "" {
			api.WriteError(w, r, api.NewError("ERRO_IDEMPOTENCIA", http.StatusUnprocessableEntity, "missing idempotency key header"))
			return
		}

		// Read and cache request body for comparison or forwarding
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			api.WriteError(w, r, api.NewError("ERRO_IDEMPOTENCIA", http.StatusBadRequest, "unable to read request body"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		rec, err := service.Response(r.Context(), idempotencyID)
		if err == nil {
			// Validate if the current request body matches the stored one.
			if string(bodyBytes) != rec.Request {
				slog.DebugContext(r.Context(),
					"mismatched idempotent request payload",
					slog.String("id", rec.ID),
					slog.String("got", string(bodyBytes)),
					slog.String("expected", rec.Request),
				)
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

		err = service.Create(r.Context(), &Record{
			ID:         idempotencyID,
			Request:    string(bodyBytes),
			Response:   recorder.Body.String(),
			StatusCode: recorder.StatusCode,
		})
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to store idempotent response", slog.Any("err", err))
		}
	})
}

func writeIdempotencyResp(w http.ResponseWriter, r *http.Request, rec *Record) {
	w.WriteHeader(rec.StatusCode)

	if len(rec.Response) == 0 {
		slog.DebugContext(r.Context(), "idempotency record has no response body", slog.String("id", rec.ID))
		return
	}

	if _, err := w.Write([]byte(rec.Response)); err != nil {
		slog.ErrorContext(r.Context(), "failed to write cached idempotent response body", slog.Any("err", err))
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
