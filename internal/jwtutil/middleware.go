package jwtutil

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

func Middleware(baseURL, bankOrgID, keystoreHost string, signer crypto.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		next = requestMiddlewareHandler(next, baseURL, keystoreHost)
		next = responseMiddlewareHandler(next, bankOrgID, signer)
		return next
	}
}

func requestMiddlewareHandler(next http.Handler, baseURL, keystoreHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}

		jwsBytes, err := io.ReadAll(r.Body)
		if err != nil {
			slog.InfoContext(r.Context(), "failed to read request jwt body", "error", err)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "failed to read request body"))
			return
		}
		defer r.Body.Close()

		jws := string(jwsBytes)
		parsedJWT, err := jwt.ParseSigned(jws, []jose.SignatureAlgorithm{goidc.PS256})
		if err != nil {
			slog.InfoContext(r.Context(), "invalid jwt", "error", err)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "invalid jwt"))
			return
		}

		clientOrgID := r.Context().Value(api.CtxKeyOrgID).(string)
		resp, err := http.Get(keystoreHost + fmt.Sprintf("/%s/application.jwks", clientOrgID))
		if err != nil {
			slog.InfoContext(r.Context(), "failed to fetch jwks", "error", err)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "failed to fetch jwks"))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			slog.InfoContext(r.Context(), "failed to fetch jwks", "status", resp.StatusCode)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "failed to fetch jwks"))
			return
		}

		var jwks jose.JSONWebKeySet
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			slog.InfoContext(r.Context(), "failed to decode jwks", "error", err)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "failed to decode organization jwks"))
			return
		}

		var jwtClaims jwt.Claims
		var claims map[string]any
		if err := parsedJWT.Claims(jwks, &jwtClaims, &claims); err != nil {
			slog.InfoContext(r.Context(), "invalid jwt signature", "error", err)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "invalid jwt signature"))
			return
		}

		if jwtClaims.IssuedAt == nil {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "iat claim is missing"))
			return
		}

		if jwtClaims.ID == "" {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "jti claim is missing"))
			return
		}

		if err := jwtClaims.Validate(jwt.Expected{
			Issuer:      clientOrgID,
			AnyAudience: []string{baseURL + r.URL.Path},
		}); err != nil {
			slog.InfoContext(r.Context(), "invalid jwt claims", slog.String("error", err.Error()))
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "JWT validation failed"))
			return
		}

		claims = map[string]any{
			"data": claims["data"],
		}

		jsonBytes, err := json.Marshal(claims)
		if err != nil {
			slog.InfoContext(r.Context(), "failed to convert claims to json", "error", err)
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "failed to convert claims to json"))
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(jsonBytes))
		r.ContentLength = int64(len(jsonBytes))
		r.Header.Set("Content-Type", "application/json")

		next.ServeHTTP(w, r)
	})
}

func responseMiddlewareHandler(next http.Handler, bankOrgID string, signer crypto.Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{
			ResponseWriter: w,
			Body:           &bytes.Buffer{},
			StatusCode:     http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		if rec.Body.Len() == 0 {
			w.WriteHeader(rec.StatusCode)
			return
		}

		if !slices.Contains([]int{
			http.StatusOK,
			http.StatusCreated,
			http.StatusAccepted,
			http.StatusUnprocessableEntity,
		}, rec.StatusCode) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.StatusCode)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}

		var respPayload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &respPayload); err != nil {
			api.WriteError(w, r, fmt.Errorf("failed to parse response for jwt encoding: %w", err))
			return
		}

		respPayload["iss"] = bankOrgID
		respPayload["aud"] = r.Context().Value(api.CtxKeyOrgID)
		respPayload["jti"] = uuid.NewString()
		now := timeutil.Timestamp()
		respPayload["iat"] = now

		jwsResp, err := Sign(respPayload, signer)
		if err != nil {
			api.WriteError(w, r, fmt.Errorf("failed to sign jwt: %w", err))
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(rec.StatusCode)
		_, _ = w.Write([]byte(jwsResp))
	})
}

type responseRecorder struct {
	http.ResponseWriter
	Body       *bytes.Buffer
	StatusCode int
}

func (rr *responseRecorder) WriteHeader(statusCode int) {
	rr.StatusCode = statusCode
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	return rr.Body.Write(b)
}
