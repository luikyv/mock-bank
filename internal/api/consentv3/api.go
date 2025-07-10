//go:generate oapi-codegen -config=./config.yml -package=consentv3 -o=./api_gen.go ./swagger.yml
package consentv3

import (
	"context"
	"errors"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type Server struct {
	baseURL string
	service consent.Service
	op      *provider.Provider
}

func NewServer(host string, service consent.Service, op *provider.Provider) Server {
	return Server{
		baseURL: host + "/open-banking/consents/v3",
		service: service,
		op:      op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	consentMux := http.NewServeMux()

	clientCredentialsAuthMiddleware := middleware.Auth(s.op, goidc.GrantClientCredentials, consent.Scope)
	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID, consent.ScopeID)
	swaggerMiddleware, _ := middleware.Swagger(GetSwagger, func(err error) api.Error {
		return api.NewError("PARAMETRO_INVALIDO", http.StatusBadRequest, err.Error())
	})

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{swaggerMiddleware},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.ConsentsPostConsents)
	handler = clientCredentialsAuthMiddleware(handler)
	consentMux.Handle("POST /consents", handler)

	handler = http.HandlerFunc(wrapper.ConsentsDeleteConsentsConsentID)
	handler = clientCredentialsAuthMiddleware(handler)
	consentMux.Handle("DELETE /consents/{consentId}", handler)

	handler = http.HandlerFunc(wrapper.ConsentsGetConsentsConsentID)
	handler = clientCredentialsAuthMiddleware(handler)
	consentMux.Handle("GET /consents/{consentId}", handler)

	handler = http.HandlerFunc(wrapper.ConsentsPostConsentsConsentIDExtends)
	handler = authCodeAuthMiddleware(handler)
	consentMux.Handle("POST /consents/{consentId}/extends", handler)

	handler = http.HandlerFunc(wrapper.ConsentsGetConsentsConsentIDExtensions)
	handler = clientCredentialsAuthMiddleware(handler)
	consentMux.Handle("GET /consents/{consentId}/extensions", handler)

	handler = middleware.FAPIID()(consentMux)
	mux.Handle("/open-banking/consents/v3/", http.StripPrefix("/open-banking/consents/v3", handler))
}

func (s Server) ConsentsPostConsents(ctx context.Context, req ConsentsPostConsentsRequestObject) (ConsentsPostConsentsResponseObject, error) {
	var perms []consent.Permission
	for _, p := range req.Body.Data.Permissions {
		perms = append(perms, consent.Permission(p))
	}
	c := &consent.Consent{
		Status:             consent.StatusAwaitingAuthorization,
		UserIdentification: req.Body.Data.LoggedUser.Document.Identification,
		UserRel:            consent.Relation(req.Body.Data.LoggedUser.Document.Rel),
		Permissions:        perms,
		ExpiresAt:          req.Body.Data.ExpirationDateTime,
		ClientID:           ctx.Value(api.CtxKeyClientID).(string),
		OrgID:              ctx.Value(api.CtxKeyOrgID).(string),
	}

	if business := req.Body.Data.BusinessEntity; business != nil {
		rel := consent.Relation(business.Document.Rel)
		c.BusinessIdentification = &business.Document.Identification
		c.BusinessRel = &rel
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
			CreationDateTime     timeutil.DateTime                `json:"creationDateTime"`
			ExpirationDateTime   *timeutil.DateTime               `json:"expirationDateTime,omitempty"`
			Permissions          []ResponseConsentDataPermissions `json:"permissions"`
			Status               ResponseConsentDataStatus        `json:"status"`
			StatusUpdateDateTime timeutil.DateTime                `json:"statusUpdateDateTime"`
		}{
			ConsentID:            c.URN(),
			Status:               ResponseConsentDataStatus(c.Status),
			Permissions:          respPerms,
			CreationDateTime:     c.CreatedAt,
			StatusUpdateDateTime: c.StatusUpdatedAt,
			ExpirationDateTime:   c.ExpiresAt,
		},
		Links: api.NewLinks(s.baseURL + "/consents/" + c.URN()),
		Meta:  api.NewMeta(),
	}

	return ConsentsPostConsents201JSONResponse{N201ConsentsCreatedJSONResponse(resp)}, nil
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
			CreationDateTime   timeutil.DateTime                    `json:"creationDateTime"`
			ExpirationDateTime *timeutil.DateTime                   `json:"expirationDateTime,omitempty"`
			Permissions        []ResponseConsentReadDataPermissions `json:"permissions"`
			Rejection          *struct {
				Reason struct {
					AdditionalInformation *string                                    `json:"additionalInformation,omitempty"`
					Code                  ResponseConsentReadDataRejectionReasonCode `json:"code"`
				} `json:"reason"`
				RejectedBy EnumRejectedBy `json:"rejectedBy"`
			} `json:"rejection,omitempty"`
			Status               ResponseConsentReadDataStatus `json:"status"`
			StatusUpdateDateTime timeutil.DateTime             `json:"statusUpdateDateTime"`
		}{
			ConsentID:            c.URN(),
			CreationDateTime:     c.CreatedAt,
			Permissions:          respPerms,
			Status:               ResponseConsentReadDataStatus(c.Status),
			StatusUpdateDateTime: c.StatusUpdatedAt,
			ExpirationDateTime:   c.ExpiresAt,
		},
		Links: api.NewLinks(s.baseURL + "/consents/" + c.URN()),
		Meta:  api.NewMeta(),
	}

	if c.Rejection != nil {
		resp.Data.Rejection = &struct {
			Reason struct {
				AdditionalInformation *string                                    `json:"additionalInformation,omitempty"`
				Code                  ResponseConsentReadDataRejectionReasonCode `json:"code"`
			} `json:"reason"`
			RejectedBy EnumRejectedBy `json:"rejectedBy"`
		}{}
		resp.Data.Rejection.RejectedBy = EnumRejectedBy(c.Rejection.By)
		resp.Data.Rejection.Reason.Code = ResponseConsentReadDataRejectionReasonCode(c.Rejection.Reason)
	}
	return ConsentsGetConsentsConsentID200JSONResponse{N200ConsentsConsentIDReadJSONResponse(resp)}, nil
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
		UserIdentification: req.Body.Data.LoggedUser.Document.Identification,
		UserRel:            consent.Relation(req.Body.Data.LoggedUser.Document.Rel),
		ExpiresAt:          req.Body.Data.ExpirationDateTime,
		UserAgent:          req.Params.XCustomerUserAgent,
		UserIPAddress:      req.Params.XFapiCustomerIPAddress,
	}

	if req.Body.Data.BusinessEntity != nil {
		ext.BusinessIdentification = &req.Body.Data.BusinessEntity.Document.Identification
		rel := consent.Relation(req.Body.Data.BusinessEntity.Document.Rel)
		ext.BusinessRel = &rel
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
			CreationDateTime     timeutil.DateTime                          `json:"creationDateTime"`
			ExpirationDateTime   *timeutil.DateTime                         `json:"expirationDateTime,omitempty"`
			Permissions          []ResponseConsentExtensionsDataPermissions `json:"permissions"`
			Status               ResponseConsentExtensionsDataStatus        `json:"status"`
			StatusUpdateDateTime timeutil.DateTime                          `json:"statusUpdateDateTime"`
		}{
			ConsentID:            c.URN(),
			CreationDateTime:     c.CreatedAt,
			Permissions:          respPerms,
			Status:               ResponseConsentExtensionsDataStatus(c.Status),
			StatusUpdateDateTime: c.StatusUpdatedAt,
			ExpirationDateTime:   c.ExpiresAt,
		},
	}
	return ConsentsPostConsentsConsentIDExtends201JSONResponse{N201ConsentsCreatedExtensionsJSONResponse(resp)}, nil
}

func (s Server) ConsentsGetConsentsConsentIDExtensions(ctx context.Context, req ConsentsGetConsentsConsentIDExtensionsRequestObject) (ConsentsGetConsentsConsentIDExtensionsResponseObject, error) {

	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	exts, err := s.service.Extensions(ctx, req.ConsentID, orgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseConsentReadExtensions{
		Links: api.NewPaginatedLinks(s.baseURL+"/consents/"+req.ConsentID+"/extensions", exts),
		Meta:  api.NewPaginatedMeta(exts),
	}
	for _, ext := range exts.Records {
		extResp := struct {
			ExpirationDateTime         *timeutil.DateTime   `json:"expirationDateTime,omitempty"`
			LoggedUser                 LoggedUserExtensions `json:"loggedUser"`
			PreviousExpirationDateTime *timeutil.DateTime   `json:"previousExpirationDateTime,omitempty"`
			RequestDateTime            timeutil.DateTime    `json:"requestDateTime"`
			XCustomerUserAgent         *string              `json:"xCustomerUserAgent,omitempty"`
			XFapiCustomerIPAddress     *string              `json:"xFapiCustomerIpAddress,omitempty"`
		}{
			LoggedUser: LoggedUserExtensions{
				Document: LoggedUserDocumentExtensions{
					Identification: ext.UserIdentification,
					Rel:            consent.DefaultUserDocumentRelation,
				},
			},
			RequestDateTime:            ext.RequestedAt,
			ExpirationDateTime:         ext.ExpiresAt,
			PreviousExpirationDateTime: ext.PreviousExpiresAt,
			XCustomerUserAgent:         &ext.UserAgent,
			XFapiCustomerIPAddress:     &ext.UserIPAddress,
		}

		resp.Data = append(resp.Data, extResp)
	}

	return ConsentsGetConsentsConsentIDExtensions200JSONResponse{N200ConsentsConsentIDReadExtensionsJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, consent.ErrAccessNotAllowed) {
		api.WriteError(w, r, api.NewError("FORBIDDEN", http.StatusForbidden, consent.ErrAccessNotAllowed.Error()))
		return
	}

	if errors.Is(err, consent.ErrExtensionNotAllowed) {
		api.WriteError(w, r, api.NewError("FORBIDDEN", http.StatusForbidden, consent.ErrExtensionNotAllowed.Error()))
		return
	}

	if errors.Is(err, consent.ErrInvalidPermissionGroup) {
		api.WriteError(w, r, api.NewError("COMBINACAO_PERMISSOES_INCORRETA", http.StatusUnprocessableEntity, consent.ErrInvalidPermissionGroup.Error()))
		return
	}

	if errors.Is(err, consent.ErrPersonalAndBusinessPermissionsTogether) {
		api.WriteError(w, r, api.NewError("PERMISSAO_PF_PJ_EM_CONJUNTO", http.StatusUnprocessableEntity, consent.ErrPersonalAndBusinessPermissionsTogether.Error()))
		return
	}

	if errors.Is(err, consent.ErrInvalidExpiration) {
		api.WriteError(w, r, api.NewError("DATA_EXPIRACAO_INVALIDA", http.StatusUnprocessableEntity, consent.ErrInvalidExpiration.Error()))
		return
	}

	if errors.Is(err, consent.ErrAlreadyRejected) {
		api.WriteError(w, r, api.NewError("CONSENTIMENTO_EM_STATUS_REJEITADO", http.StatusUnprocessableEntity, consent.ErrAlreadyRejected.Error()))
		return
	}

	if errors.Is(err, consent.ErrCannotExtendConsentNotAuthorized) {
		api.WriteError(w, r, api.NewError("ESTADO_CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, consent.ErrCannotExtendConsentNotAuthorized.Error()))
		return
	}

	if errors.Is(err, consent.ErrCannotExtendConsentForJointAccount) {
		api.WriteError(w, r, api.NewError("DEPENDE_MULTIPLA_ALCADA", http.StatusUnprocessableEntity, consent.ErrCannotExtendConsentForJointAccount.Error()))
		return
	}

	if errors.As(err, &errorutil.Error{}) {
		api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}
