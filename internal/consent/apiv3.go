package consent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/api/middleware"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

var (
	errBadRequest = api.NewError("INVALID_REQUEST", http.StatusBadRequest, "invalid request")
)

type ServerV3 struct {
	host    string
	service Service
	op      *provider.Provider
}

func NewServerV3(host string, service Service, op *provider.Provider) ServerV3 {
	return ServerV3{
		host:    host,
		service: service,
		op:      op,
	}
}

func (s ServerV3) Register(mux *http.ServeMux) {
	consentMux := http.NewServeMux()

	handler := s.createHandler()
	handler = middleware.AuthScopes(handler, s.op, []goidc.Scope{Scope}, nil)
	consentMux.Handle("POST /open-banking/consents/v3/consents", handler)

	handler = s.consentHandler()
	handler = middleware.AuthScopes(handler, s.op, []goidc.Scope{Scope}, nil)
	consentMux.Handle("GET /open-banking/consents/v3/consents/{id}", handler)

	handler = s.deleteHandler()
	handler = middleware.AuthScopes(handler, s.op, []goidc.Scope{Scope}, nil)
	consentMux.Handle("DELETE /open-banking/consents/v3/consents/{id}", handler)

	handler = s.extendHandler()
	handler = middleware.AuthScopes(handler, s.op, []goidc.Scope{goidc.ScopeOpenID, ScopeID}, nil)
	consentMux.Handle("POST /open-banking/consents/v3/consents/{id}/extends", handler)

	handler = s.extensionsHandler()
	handler = middleware.AuthScopes(handler, s.op, []goidc.Scope{Scope}, nil)
	consentMux.Handle("GET /open-banking/consents/v3/consents/{id}/extensions", handler)

	handler = consentMux
	handler = middleware.FAPIID(handler, nil)
	handler = middleware.Meta(handler, s.host)
	mux.Handle("/open-banking/consents/", handler)
}

func (s ServerV3) createHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req createRequestV3
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteError(w, errBadRequest)
			return
		}

		if err := req.validate(); err != nil {
			writeErrorV3(w, err)
			return
		}

		c := req.toConsent(r.Context())
		if err := s.service.create(r.Context(), c); err != nil {
			writeErrorV3(w, err)
			return
		}

		resp := toResponseV3(c, s.host)
		api.WriteJSON(w, resp, http.StatusCreated)
	})
}

func (s ServerV3) consentHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		c, err := s.service.Consent(r.Context(), id)
		if err != nil {
			writeErrorV3(w, err)
			return
		}

		resp := toResponseV3(c, s.host)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

func (s ServerV3) deleteHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		err := s.service.delete(r.Context(), id)
		if err != nil {
			writeErrorV3(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func (s ServerV3) extendHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id != r.Context().Value(api.CtxKeyConsentID) {
			api.WriteError(w, errBadRequest)
			return
		}

		ip := r.Header.Get(api.HeaderCustomerIPAddress)
		if ip == "" {
			api.WriteError(w, errBadRequest)
			return
		}

		userAgent := r.Header.Get(api.HeaderCustomerUserAgent)
		if userAgent == "" {
			api.WriteError(w, errBadRequest)
			return
		}

		var req extendRequestV3
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteError(w, errBadRequest)
			return
		}

		if err := req.validate(); err != nil {
			writeErrorV3(w, err)
			return
		}

		c, err := s.service.extend(r.Context(), id, req.toExtension(ip, userAgent))
		if err != nil {
			writeErrorV3(w, err)
			return
		}

		resp := toResponseV3(c, s.host)
		api.WriteJSON(w, resp, http.StatusCreated)
	})
}

func (s ServerV3) extensionsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		pag, err := api.NewPagination(r)
		if err != nil {
			writeErrorV3(w, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, err.Error()))
			return
		}

		exts, err := s.service.extensions(r.Context(), id, pag)
		if err != nil {
			writeErrorV3(w, err)
			return
		}

		resp := toExtensionsResponseV3(exts, s.host)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

type createRequestV3 struct {
	Data struct {
		LoggerUser         entityV3  `json:"loggedUser"`
		BusinessEntity     *entityV3 `json:"businessEntity,omitempty"`
		Permissions        []Permission
		ExpirationDateTime *timex.DateTime
	} `json:"data"`
}

type entityV3 struct {
	Document documentV3 `json:"document"`
}

type documentV3 struct {
	Identification string `json:"identification"`
	Relation       string `json:"rel"`
}

func (req createRequestV3) validate() error {
	for _, p := range req.Data.Permissions {
		if !slices.Contains(PermissionGroupAll, p) {
			return api.NewError("INVALID_PERMISSION", http.StatusBadRequest, "invalid request")
		}
	}
	return nil
}

func (req createRequestV3) toConsent(ctx context.Context) Consent {
	c := Consent{
		ID:              consentID(),
		Status:          StatusAwaitingAuthorization,
		UserCPF:         req.Data.LoggerUser.Document.Identification,
		Permissions:     req.Data.Permissions,
		ExpiresAt:       &req.Data.ExpirationDateTime.Time,
		CreatedAt:       timex.Now(),
		StatusUpdatedAt: timex.Now(),
		ClientID:        ctx.Value(api.CtxKeyClientID).(string),
		OrgID:           ctx.Value(api.CtxKeyOrgID).(string),
	}

	if req.Data.BusinessEntity != nil {
		c.BusinessCNPJ = req.Data.BusinessEntity.Document.Identification
	}

	return c
}

type responseV3 struct {
	Data struct {
		ID                   string          `json:"consentId"`
		Status               Status          `json:"status"`
		Permissions          []Permission    `json:"permissions"`
		CreationDateTime     timex.DateTime  `json:"creationDateTime"`
		StatusUpdateDateTime timex.DateTime  `json:"statusUpdateDateTime"`
		ExpirationDateTime   *timex.DateTime `json:"expirationDateTime,omitempty"`
		Rejection            *struct {
			RejectedBy RejectedBy `json:"rejectedBy"`
			Reason     struct {
				Code RejectionReason `json:"code"`
			} `json:"reason"`
		} `json:"rejection,omitempty"`
	} `json:"data"`
	Links api.Links `json:"links"`
	Meta  api.Meta  `json:"meta"`
}

func toResponseV3(c Consent, host string) responseV3 {
	resp := responseV3{
		Links: api.NewLinks(host + "/open-banking/consents/v3/consents/" + c.ID),
		Meta:  api.NewMeta(),
	}
	resp.Data.ID = c.ID
	resp.Data.Status = c.Status
	resp.Data.Permissions = c.Permissions
	resp.Data.CreationDateTime = timex.NewDateTime(c.CreatedAt)
	resp.Data.StatusUpdateDateTime = timex.NewDateTime(c.StatusUpdatedAt)
	if c.ExpiresAt != nil {
		exp := timex.NewDateTime(*c.ExpiresAt)
		resp.Data.ExpirationDateTime = &exp
	}

	if c.RejectedBy != "" {
		resp.Data.Rejection = &struct {
			RejectedBy RejectedBy `json:"rejectedBy"`
			Reason     struct {
				Code RejectionReason `json:"code"`
			} `json:"reason"`
		}{
			RejectedBy: c.RejectedBy,
			Reason: struct {
				Code RejectionReason `json:"code"`
			}{
				Code: c.RejectionReason,
			},
		}
	}

	return resp
}

type extendRequestV3 struct {
	Data struct {
		ExpirationDateTime *timex.DateTime
		LoggerUser         entityV3  `json:"loggedUser"`
		BusinessEntity     *entityV3 `json:"businessEntity,omitempty"`
	} `json:"data"`
}

func (r extendRequestV3) validate() error {
	return nil
}

func (r extendRequestV3) toExtension(ip, userAgent string) Extension {
	ext := Extension{
		UserCPF:       r.Data.LoggerUser.Document.Identification,
		UserIPAddress: ip,
		UserAgent:     userAgent,
	}
	if r.Data.ExpirationDateTime != nil {
		ext.ExpiresAt = &r.Data.ExpirationDateTime.Time
	}
	if r.Data.BusinessEntity != nil {
		ext.BusinessCNPJ = r.Data.BusinessEntity.Document.Identification
	}

	return ext
}

type extensionsResponseV3 struct {
	Data  []extensionResponseV3 `json:"data"`
	Links api.Links             `json:"links"`
	Meta  api.Meta              `json:"meta"`
}

type extensionResponseV3 struct {
	ExpirationDateTime         *timex.DateTime `json:"expirationDateTime,omitempty"`
	PreviousExpirationDateTime *timex.DateTime `json:"previousExpirationDateTime,omitempty"`
	LoggerUser                 entityV3        `json:"loggedUser"`
	RequestDateTime            timex.DateTime  `json:"requestDateTime"`
	CustomerIPAddress          string          `json:"xFapiCustomerIpAddress"`
	CustomerUserAgent          string          `json:"xCustomerUserAgent"`
}

func toExtensionsResponseV3(exts page.Page[Extension], reqURL string) extensionsResponseV3 {
	resp := extensionsResponseV3{
		Links: api.Links{
			Self: reqURL,
		},
		Meta: api.NewPaginatedMeta(exts),
	}

	for _, ext := range exts.Records {
		extResp := extensionResponseV3{
			LoggerUser: entityV3{
				Document: documentV3{
					Identification: ext.UserCPF,
					Relation:       defaultUserDocumentRelation,
				},
			},
			RequestDateTime:   timex.NewDateTime(ext.RequestedAt),
			CustomerIPAddress: ext.UserIPAddress,
			CustomerUserAgent: ext.UserAgent,
		}
		if ext.ExpiresAt != nil {
			exp := timex.NewDateTime(*ext.ExpiresAt)
			extResp.ExpirationDateTime = &exp
		}
		if ext.PreviousExpiresAt != nil {
			exp := timex.NewDateTime(*ext.PreviousExpiresAt)
			extResp.PreviousExpirationDateTime = &exp
		}

		resp.Data = append(resp.Data, extResp)
	}

	return resp
}

func writeErrorV3(w http.ResponseWriter, err error) {
	if errors.Is(err, errAccessNotAllowed) {
		api.WriteError(w, api.NewError("FORBIDDEN", http.StatusForbidden, errAccessNotAllowed.Error()))
		return
	}

	if errors.Is(err, errExtensionNotAllowed) {
		api.WriteError(w, api.NewError("FORBIDDEN", http.StatusForbidden, errExtensionNotAllowed.Error()))
		return
	}

	if errors.Is(err, errInvalidPermissionGroup) {
		api.WriteError(w, api.NewError("COMBINACAO_PERMISSOES_INCORRETA", http.StatusUnprocessableEntity, errInvalidPermissionGroup.Error()))
		return
	}

	if errors.Is(err, errPersonalAndBusinessPermissionsTogether) {
		api.WriteError(w, api.NewError("PERMISSAO_PF_PJ_EM_CONJUNTO", http.StatusUnprocessableEntity, errPersonalAndBusinessPermissionsTogether.Error()))
		return
	}

	if errors.Is(err, errInvalidExpiration) {
		api.WriteError(w, api.NewError("DATA_EXPIRACAO_INVALIDA", http.StatusUnprocessableEntity, errInvalidExpiration.Error()))
		return
	}

	if errors.Is(err, errAlreadyRejected) {
		api.WriteError(w, api.NewError("CONSENTIMENTO_EM_STATUS_REJEITADO", http.StatusUnprocessableEntity, errAlreadyRejected.Error()))
		return
	}

	if errors.Is(err, errCannotExtendConsentNotAuthorized) {
		api.WriteError(w, api.NewError("ESTADO_CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, errCannotExtendConsentNotAuthorized.Error()))
		return
	}

	if errors.Is(err, errCannotExtendConsentForJointAccount) {
		api.WriteError(w, api.NewError("DEPENDE_MULTIPLA_ALCADA", http.StatusUnprocessableEntity, errCannotExtendConsentForJointAccount.Error()))
		return
	}

	api.WriteError(w, errBadRequest)
}
