package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/oidc"
)

func Auth(op *provider.Provider, grantType goidc.GrantType, scopes ...goidc.Scope) func(http.Handler) http.Handler {
	return AuthWithOptions(op, grantType, nil, scopes...)
}

func AuthWithOptions(op *provider.Provider, grantType goidc.GrantType, opts *Options, scopes ...goidc.Scope) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &Options{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			tokenInfo, err := op.TokenInfoFromRequest(w, r)
			if err != nil {
				slog.InfoContext(ctx, "the token is not active", "error", err)
				api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token").Pagination(opts.ErrorPagination))
				return
			}

			ctx = context.WithValue(ctx, api.CtxKeyClientID, tokenInfo.ClientID)
			ctx = context.WithValue(ctx, api.CtxKeySubject, tokenInfo.Subject)
			ctx = context.WithValue(ctx, api.CtxKeyScopes, tokenInfo.Scopes)
			ctx = context.WithValue(ctx, api.CtxKeyOrgID, tokenInfo.AdditionalTokenClaims[oidc.OrgIDKey])
			r = r.WithContext(ctx)

			switch grantType {
			case goidc.GrantClientCredentials:
				// Client credentials tokens are issued for the client itself, so the subject must be the client ID.
				if tokenInfo.Subject != tokenInfo.ClientID {
					slog.InfoContext(ctx, "invalid token grant type, client credentials is required", "sub", tokenInfo.Subject, "client_id", tokenInfo.ClientID)
					api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token grant type, client credentials is required").Pagination(opts.ErrorPagination))
					return
				}
			case goidc.GrantAuthorizationCode:
				// Authorization code tokens are issued for a user, so the subject must not be the client ID.
				if tokenInfo.Subject == tokenInfo.ClientID {
					slog.InfoContext(ctx, "invalid token grant type, authorization code is required", "sub", tokenInfo.Subject, "client_id", tokenInfo.ClientID)
					api.WriteError(w, r, api.NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token grant type, authorization code is required").Pagination(opts.ErrorPagination))
					return
				}
			}

			tokenScopes := strings.Split(tokenInfo.Scopes, " ")
			if !areScopesValid(scopes, tokenScopes) {
				slog.InfoContext(ctx, "invalid scopes", "token_scopes", tokenInfo.Scopes)
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
