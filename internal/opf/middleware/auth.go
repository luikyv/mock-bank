package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func Auth(next http.Handler, op *provider.Provider, scopes ...goidc.Scope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Header.Get(HeaderXFAPIInteractionID) != "" {
			ctx = context.WithValue(r.Context(), opf.CtxKeyInteractionID, r.Header.Get(HeaderXFAPIInteractionID))
		}

		tokenInfo, err := op.TokenInfoFromRequest(w, r)
		if err != nil {
			slog.DebugContext(r.Context(), "the token is not active")
			api.WriteJSON(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token").Pagination(true), http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, opf.CtxKeyClientID, tokenInfo.ClientID)
		ctx = context.WithValue(ctx, opf.CtxKeySubject, tokenInfo.Subject)
		ctx = context.WithValue(ctx, opf.CtxKeyScopes, tokenInfo.Scopes)
		ctx = context.WithValue(ctx, opf.CtxKeyOrgID, tokenInfo.AdditionalTokenClaims["org_id"])
		r = r.WithContext(ctx)

		tokenScopes := strings.Split(tokenInfo.Scopes, " ")
		if !areScopesValid(scopes, tokenScopes) {
			slog.DebugContext(r.Context(), "invalid scopes", slog.String("token_scopes", tokenInfo.Scopes))
			api.WriteJSON(w, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "token missing scopes").Pagination(true), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
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
