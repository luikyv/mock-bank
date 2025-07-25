package middleware

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
	"github.com/luikyv/mock-bank/internal/jwtutil"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

// JWT creates a middleware that handles JWT request/response processing.
// It validates incoming JWT requests and signs outgoing JWT responses.
func JWT(baseURL, bankOrgID, keystoreHost string, signer crypto.Signer, service jwtutil.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		next = requestMiddlewareHandler(next, baseURL, keystoreHost, service)
		next = responseMiddlewareHandler(next, bankOrgID, signer)
		return next
	}
}

// requestMiddlewareHandler processes incoming JWT requests by validating the JWT signature,
// claims, and extracting the payload data for downstream handlers.
func requestMiddlewareHandler(next http.Handler, baseURL, keystoreHost string, service jwtutil.Service) http.Handler {
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

		if jwtClaims.Issuer != clientOrgID {
			api.WriteError(w, r, api.NewError("FORBIDDEN", http.StatusForbidden, "iss claim does not match the client org id"))
			return
		}

		if err := jwtClaims.Validate(jwt.Expected{
			AnyAudience: []string{baseURL + r.URL.Path},
		}); err != nil {
			slog.InfoContext(r.Context(), "invalid jwt claims", slog.String("error", err.Error()))
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "JWT validation failed"))
			return
		}

		jtiIsValid, err := service.CheckJTI(r.Context(), jwtClaims.ID, clientOrgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to check jti", "error", err)
			api.WriteError(w, r, fmt.Errorf("failed to check jti: %w", err))
			return
		}

		if !jtiIsValid {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, "jti is invalid"))
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

// responseMiddlewareHandler processes outgoing responses by wrapping them in a JWT
// with the bank's signature and required claims.
func responseMiddlewareHandler(next http.Handler, bankOrgID string, signer crypto.Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &responseBuffer{
			ResponseWriter: w,
			Body:           &bytes.Buffer{},
			StatusCode:     http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		if rec.Body.Len() == 0 {
			w.WriteHeader(rec.StatusCode)
			return
		}

		// Only sign successful responses and 422 responses.
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
		respPayload["iat"] = timeutil.Timestamp()

		jwsResp, err := jwtutil.Sign(respPayload, signer)
		if err != nil {
			api.WriteError(w, r, fmt.Errorf("failed to sign jwt: %w", err))
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(rec.StatusCode)
		_, _ = w.Write([]byte(jwsResp))
	})
}

// responseBuffer captures the response from downstream handlers to allow
// JWT processing before sending to the client.
type responseBuffer struct {
	http.ResponseWriter
	Body       *bytes.Buffer
	StatusCode int
}

func (rr *responseBuffer) WriteHeader(statusCode int) {
	rr.StatusCode = statusCode
}

func (rr *responseBuffer) Write(b []byte) (int, error) {
	return rr.Body.Write(b)
}
