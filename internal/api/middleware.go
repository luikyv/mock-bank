package api

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

type Options struct {
	ErrorPagination bool
}

func AuthHandler(next http.Handler, op *provider.Provider, scopes ...goidc.Scope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Header.Get(HeaderXFAPIInteractionID) != "" {
			ctx = context.WithValue(r.Context(), CtxKeyInteractionID, r.Header.Get(HeaderXFAPIInteractionID))
		}

		tokenInfo, err := op.TokenInfoFromRequest(w, r)
		if err != nil {
			slog.DebugContext(r.Context(), "the token is not active")
			WriteError(w, NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token").Pagination(true))
			return
		}

		ctx = context.WithValue(ctx, CtxKeyClientID, tokenInfo.ClientID)
		ctx = context.WithValue(ctx, CtxKeySubject, tokenInfo.Subject)
		ctx = context.WithValue(ctx, CtxKeyScopes, tokenInfo.Scopes)
		ctx = context.WithValue(ctx, CtxKeyOrgID, tokenInfo.AdditionalTokenClaims["org_id"])
		r = r.WithContext(ctx)

		tokenScopes := strings.Split(tokenInfo.Scopes, " ")
		if !areScopesValid(scopes, tokenScopes) {
			slog.DebugContext(r.Context(), "invalid scopes", slog.String("token_scopes", tokenInfo.Scopes))
			WriteError(w, NewError("UNAUTHORISED", http.StatusUnauthorized, "token missing scopes").Pagination(true))
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

func PermissionMiddleware(next http.Handler, consentService consent.Service, permissions ...consent.Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes := r.Context().Value(CtxKeyScopes).(string)
		orgID := r.Context().Value(CtxKeyOrgID).(string)

		consentID, _ := consent.IDFromScopes(scopes)
		consent, err := consentService.Consent(r.Context(), consentID, orgID)
		if err != nil {
			slog.DebugContext(r.Context(), "the token is not active")
			WriteError(w, NewError("UNAUTHORISED", http.StatusUnauthorized, "invalid token"))
			return
		}

		if !consent.IsAuthorized() {
			slog.DebugContext(r.Context(), "the consent is not authorized")
			WriteError(w, NewError("INVALID_STATUS", http.StatusUnauthorized, "the consent is not authorized"))
			return
		}

		if !consent.HasPermissions(permissions) {
			slog.DebugContext(r.Context(), "the consent doesn't have the required permissions")
			WriteError(w, NewError("INVALID_STATUS", http.StatusForbidden, "the consent is missing permissions"))
		}

		r = r.WithContext(context.WithValue(r.Context(), CtxKeyConsentID, consentID))
		next.ServeHTTP(w, r)
	})
}

func FAPIIDHandler(next http.Handler, opts *Options) http.Handler {
	if opts == nil {
		opts = &Options{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interactionID := r.Header.Get(HeaderXFAPIInteractionID)
		// Verify if the interaction ID is valid, return a new value if not.
		if _, err := uuid.Parse(interactionID); err != nil {
			w.Header().Add(HeaderXFAPIInteractionID, uuid.NewString())
			WriteError(w, NewError("INVALID_INTERACTION_ID", http.StatusBadRequest, "The fapi interaction id is missing or invalid").Pagination(opts.ErrorPagination))
			return
		}

		// Return the same interaction ID in the response.
		w.Header().Set(HeaderXFAPIInteractionID, interactionID)
		next.ServeHTTP(w, r)
	})
}

func FAPIID(opts *Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return FAPIIDHandler(next, opts)
	}
}
