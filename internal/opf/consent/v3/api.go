package v3

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/middleware"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

var _ StrictServerInterface = Server{}

type Server struct {
	host    string
	service consent.Service
	op      *provider.Provider
}

func NewServer(host string, service consent.Service, op *provider.Provider) Server {
	return Server{
		host:    host,
		service: service,
		op:      op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	strictHandler := NewStrictHandlerWithOptions(s, []StrictMiddlewareFunc{
		middleware.FAPIID(nil),
		middleware.Meta(s.host),
		middleware.AuthScopes(map[string]middleware.AuthOptions{
			"consentsPostConsents":                   {Scopes: []goidc.Scope{consent.Scope}},
			"consentsGetConsentsConsentID":           {Scopes: []goidc.Scope{consent.Scope}},
			"consentsDeleteConsentsConsentID":        {Scopes: []goidc.Scope{consent.Scope}},
			"consentsPostConsentsConsentIDExtends":   {Scopes: []goidc.Scope{consent.Scope, goidc.ScopeOpenID}},
			"consentsGetConsentsConsentIDExtensions": {Scopes: []goidc.Scope{consent.Scope}},
		}, s.op),
	}, StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeResponseError(w, err)
		},
	})
	handler := Handler(strictHandler)
	mux.Handle("/open-banking/consents/v3/", http.StripPrefix("/open-banking/consents/v3", handler))
}

func (s Server) ConsentsPostConsents(ctx context.Context, req ConsentsPostConsentsRequestObject) (ConsentsPostConsentsResponseObject, error) {
	var perms []consent.Permission
	for _, p := range req.Body.Data.Permissions {
		perms = append(perms, consent.Permission(p))
	}
	c := &consent.Consent{
		Status:      consent.StatusAwaitingAuthorization,
		UserCPF:     req.Body.Data.LoggedUser.Document.Identification,
		Permissions: perms,
		ExpiresAt:   &req.Body.Data.ExpirationDateTime.Time,
		ClientID:    ctx.Value(api.CtxKeyClientID).(string),
		OrgID:       ctx.Value(api.CtxKeyOrgID).(string),
	}
	if err := s.service.Create(ctx, c); err != nil {
		return nil, err
	}

	var respPerms []ResponseConsentDataPermissions
	for _, p := range c.Permissions {
		respPerms = append(respPerms, ResponseConsentDataPermissions(p))
	}
	resp := ResponseConsent{
		Data: struct {
			ConsentID            string                           `json:"consentId"`
			CreationDateTime     timex.DateTime                   `json:"creationDateTime"`
			ExpirationDateTime   *timex.DateTime                  `json:"expirationDateTime,omitempty"`
			Permissions          []ResponseConsentDataPermissions `json:"permissions"`
			Status               ResponseConsentDataStatus        `json:"status"`
			StatusUpdateDateTime timex.DateTime                   `json:"statusUpdateDateTime"`
		}{
			ConsentID:            c.URN(),
			Status:               ResponseConsentDataStatus(c.Status),
			Permissions:          respPerms,
			CreationDateTime:     timex.NewDateTime(c.CreatedAt),
			StatusUpdateDateTime: timex.NewDateTime(c.StatusUpdatedAt),
		},
		Links: api.NewLinks(s.host + "/open-banking/consents/v3/consents/" + c.URN()),
		Meta:  api.NewMeta(),
	}
	if c.ExpiresAt != nil {
		exp := timex.NewDateTime(*c.ExpiresAt)
		resp.Data.ExpirationDateTime = &exp
	}

	return ConsentsPostConsents201JSONResponse{N201ConsentsCreatedJSONResponse{Body: resp}}, nil
}

func (s Server) ConsentsGetConsentsConsentID(ctx context.Context, req ConsentsGetConsentsConsentIDRequestObject) (ConsentsGetConsentsConsentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	c, err := s.service.Consent(ctx, req.ConsentID, orgID)
	if err != nil {
		return nil, err
	}

	var respPerms []ResponseConsentReadDataPermissions
	for _, p := range c.Permissions {
		respPerms = append(respPerms, ResponseConsentReadDataPermissions(p))
	}
	resp := ResponseConsentRead{
		Data: struct {
			ConsentID          string                               `json:"consentId"`
			CreationDateTime   timex.DateTime                       `json:"creationDateTime"`
			ExpirationDateTime *timex.DateTime                      `json:"expirationDateTime,omitempty"`
			Permissions        []ResponseConsentReadDataPermissions `json:"permissions"`
			Rejection          *struct {
				Reason struct {
					AdditionalInformation *string                                    `json:"additionalInformation,omitempty"`
					Code                  ResponseConsentReadDataRejectionReasonCode `json:"code"`
				} `json:"reason"`
				RejectedBy EnumRejectedBy `json:"rejectedBy"`
			} `json:"rejection,omitempty"`
			Status               ResponseConsentReadDataStatus `json:"status"`
			StatusUpdateDateTime timex.DateTime                `json:"statusUpdateDateTime"`
		}{
			ConsentID:            c.URN(),
			CreationDateTime:     timex.NewDateTime(c.CreatedAt),
			Permissions:          respPerms,
			Status:               ResponseConsentReadDataStatus(c.Status),
			StatusUpdateDateTime: timex.NewDateTime(c.StatusUpdatedAt),
		},
		Links: api.NewLinks(s.host + "/open-banking/consents/v3/consents/" + c.URN()),
		Meta:  api.NewMeta(),
	}
	if c.ExpiresAt != nil {
		exp := timex.NewDateTime(*c.ExpiresAt)
		resp.Data.ExpirationDateTime = &exp
	}
	if c.RejectedBy != "" {
		resp.Data.Rejection = &struct {
			Reason struct {
				AdditionalInformation *string                                    `json:"additionalInformation,omitempty"`
				Code                  ResponseConsentReadDataRejectionReasonCode `json:"code"`
			} `json:"reason"`
			RejectedBy EnumRejectedBy `json:"rejectedBy"`
		}{}
		resp.Data.Rejection.RejectedBy = EnumRejectedBy(c.RejectedBy)
		resp.Data.Rejection.Reason.Code = ResponseConsentReadDataRejectionReasonCode(c.RejectionReason)
	}
	return ConsentsGetConsentsConsentID200JSONResponse{N200ConsentsConsentIDReadJSONResponse{
		Body: resp,
	}}, nil
}

func (s Server) ConsentsDeleteConsentsConsentID(ctx context.Context, req ConsentsDeleteConsentsConsentIDRequestObject) (ConsentsDeleteConsentsConsentIDResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	if err := s.service.Delete(ctx, req.ConsentID, orgID); err != nil {
		return nil, err
	}

	return ConsentsDeleteConsentsConsentID204Response{}, nil
}

func (s Server) ConsentsPostConsentsConsentIDExtends(ctx context.Context, req ConsentsPostConsentsConsentIDExtendsRequestObject) (ConsentsPostConsentsConsentIDExtendsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	ext := &consent.Extension{
		ConsentID:     uuid.MustParse(consentID),
		UserAgent:     req.Params.XCustomerUserAgent,
		UserIPAddress: req.Params.XFapiCustomerIPAddress,
	}

	c, err := s.service.Extend(ctx, consentID, orgID, ext)
	if err != nil {
		return nil, err
	}

	var respPerms []ResponseConsentExtensionsDataPermissions
	for _, p := range c.Permissions {
		respPerms = append(respPerms, ResponseConsentExtensionsDataPermissions(p))
	}
	resp := ResponseConsentExtensions{
		Data: struct {
			ConsentID            string                                     `json:"consentId"`
			CreationDateTime     timex.DateTime                             `json:"creationDateTime"`
			ExpirationDateTime   *timex.DateTime                            `json:"expirationDateTime,omitempty"`
			Permissions          []ResponseConsentExtensionsDataPermissions `json:"permissions"`
			Status               ResponseConsentExtensionsDataStatus        `json:"status"`
			StatusUpdateDateTime timex.DateTime                             `json:"statusUpdateDateTime"`
		}{
			ConsentID:            c.URN(),
			CreationDateTime:     timex.NewDateTime(c.CreatedAt),
			Permissions:          respPerms,
			Status:               ResponseConsentExtensionsDataStatus(c.Status),
			StatusUpdateDateTime: timex.NewDateTime(c.StatusUpdatedAt),
		},
	}
	if c.ExpiresAt != nil {
		exp := timex.NewDateTime(*c.ExpiresAt)
		resp.Data.ExpirationDateTime = &exp
	}
	return ConsentsPostConsentsConsentIDExtends201JSONResponse{N201ConsentsCreatedExtensionsJSONResponse{Body: resp}}, nil
}

func (s Server) ConsentsGetConsentsConsentIDExtensions(ctx context.Context, req ConsentsGetConsentsConsentIDExtensionsRequestObject) (ConsentsGetConsentsConsentIDExtensionsResponseObject, error) {

	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	reqURL := ctx.Value(api.CtxKeyRequestURL).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	exts, err := s.service.Extensions(ctx, req.ConsentID, orgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseConsentReadExtensions{
		Links: api.NewPaginatedLinks(reqURL, exts),
		Meta:  api.NewPaginatedMeta(exts),
	}
	for _, ext := range exts.Records {
		extResp := struct {
			ExpirationDateTime         *timex.DateTime      `json:"expirationDateTime,omitempty"`
			LoggedUser                 LoggedUserExtensions `json:"loggedUser"`
			PreviousExpirationDateTime *timex.DateTime      `json:"previousExpirationDateTime,omitempty"`
			RequestDateTime            timex.DateTime       `json:"requestDateTime"`
			XCustomerUserAgent         *string              `json:"xCustomerUserAgent,omitempty"`
			XFapiCustomerIPAddress     *string              `json:"xFapiCustomerIpAddress,omitempty"`
		}{
			LoggedUser: LoggedUserExtensions{
				Document: LoggedUserDocumentExtensions{
					Identification: ext.UserCPF,
					Rel:            consent.DefaultUserDocumentRelation,
				},
			},
			RequestDateTime:        timex.NewDateTime(ext.RequestedAt),
			XCustomerUserAgent:     &ext.UserAgent,
			XFapiCustomerIPAddress: &ext.UserIPAddress,
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

	return ConsentsGetConsentsConsentIDExtensions200JSONResponse{N200ConsentsConsentIDReadExtensionsJSONResponse{Body: resp}}, nil
}

func writeResponseError(w http.ResponseWriter, err error) {
	if errors.Is(err, consent.ErrAccessNotAllowed) {
		api.WriteError(w, api.NewError("FORBIDDEN", http.StatusForbidden, consent.ErrAccessNotAllowed.Error()))
		return
	}

	if errors.Is(err, consent.ErrExtensionNotAllowed) {
		api.WriteError(w, api.NewError("FORBIDDEN", http.StatusForbidden, consent.ErrExtensionNotAllowed.Error()))
		return
	}

	if errors.Is(err, consent.ErrInvalidPermissionGroup) {
		api.WriteError(w, api.NewError("COMBINACAO_PERMISSOES_INCORRETA", http.StatusUnprocessableEntity, consent.ErrInvalidPermissionGroup.Error()))
		return
	}

	if errors.Is(err, consent.ErrPersonalAndBusinessPermissionsTogether) {
		api.WriteError(w, api.NewError("PERMISSAO_PF_PJ_EM_CONJUNTO", http.StatusUnprocessableEntity, consent.ErrPersonalAndBusinessPermissionsTogether.Error()))
		return
	}

	if errors.Is(err, consent.ErrInvalidExpiration) {
		api.WriteError(w, api.NewError("DATA_EXPIRACAO_INVALIDA", http.StatusUnprocessableEntity, consent.ErrInvalidExpiration.Error()))
		return
	}

	if errors.Is(err, consent.ErrAlreadyRejected) {
		api.WriteError(w, api.NewError("CONSENTIMENTO_EM_STATUS_REJEITADO", http.StatusUnprocessableEntity, consent.ErrAlreadyRejected.Error()))
		return
	}

	if errors.Is(err, consent.ErrCannotExtendConsentNotAuthorized) {
		api.WriteError(w, api.NewError("ESTADO_CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, consent.ErrCannotExtendConsentNotAuthorized.Error()))
		return
	}

	if errors.Is(err, consent.ErrCannotExtendConsentForJointAccount) {
		api.WriteError(w, api.NewError("DEPENDE_MULTIPLA_ALCADA", http.StatusUnprocessableEntity, consent.ErrCannotExtendConsentForJointAccount.Error()))
		return
	}

	api.WriteError(w, api.NewError("INTERNAL_ERROR", http.StatusInternalServerError, "internal error"))
}
