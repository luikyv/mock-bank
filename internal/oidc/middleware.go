package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
)

func AuthMiddleware(op *provider.Provider, scopes ...goidc.Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if r.Header.Get(api.HeaderXFAPIInteractionID) != "" {
				ctx = context.WithValue(r.Context(), api.CtxKeyInteractionID, r.Header.Get(api.HeaderXFAPIInteractionID))
			}

			tokenInfo, err := op.TokenInfoFromRequest(w, r)
			if err != nil {
				slog.InfoContext(r.Context(), "the token is not active", "error", err.Error())
				api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token").Pagination(true))
				return
			}

			ctx = context.WithValue(ctx, api.CtxKeyClientID, tokenInfo.ClientID)
			ctx = context.WithValue(ctx, api.CtxKeySubject, tokenInfo.Subject)
			ctx = context.WithValue(ctx, api.CtxKeyScopes, tokenInfo.Scopes)
			ctx = context.WithValue(ctx, api.CtxKeyOrgID, tokenInfo.AdditionalTokenClaims[OrgIDKey])
			r = r.WithContext(ctx)

			tokenScopes := strings.Split(tokenInfo.Scopes, " ")
			if !areScopesValid(scopes, tokenScopes) {
				slog.InfoContext(r.Context(), "invalid scopes", "token_scopes", tokenInfo.Scopes)
				api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "token missing scopes").Pagination(true))
				return
			}

			next.ServeHTTP(w, r)
		})
	}

}

// areScopesValid verifies every scope in requiredScopes has a match among scopes.
// scopes can have more scopes than the defined at requiredScopes, but the contrary results in false.
func areScopesValid(requiredScopes []goidc.Scope, scopes []string) bool {
	for _, requiredScope := range requiredScopes {
		if !isScopeValid(requiredScope, scopes) {
			return false
		}
	}
	return true
}

// isScopeValid verifies if requireScope has a match in scopes.
func isScopeValid(requiredScope goidc.Scope, scopes []string) bool {
	return slices.ContainsFunc(scopes, requiredScope.Matches)
}
