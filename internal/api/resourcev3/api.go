//go:generate oapi-codegen -config=./config.yml -package=resourcev3 -o=./api_gen.go ./swagger.yml
package resourcev3

import (
	"context"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
)

var _ StrictServerInterface = Server{}

type Server struct {
	baseURL        string
	service        resource.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(host string, service resource.Service, consentService consent.Service, op *provider.Provider) Server {
	return Server{
		baseURL:        host + "/open-banking/resources/v3",
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	resourceMux := http.NewServeMux()

	swaggerMiddleware, _ := middleware.Swagger(GetSwagger, func(err error) string { return "INVALID_REQUEST" })

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{
			swaggerMiddleware,
			middleware.FAPIID(nil),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.ResourcesGetResources)
	handler = middleware.Permission(s.consentService, consent.PermissionResourcesRead)(handler)
	handler = middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID, consent.ScopeID)(handler)
	resourceMux.Handle("GET /resources", handler)

	mux.Handle("/open-banking/resources/v3/", http.StripPrefix("/open-banking/resources/v3", resourceMux))
}

func (s Server) ResourcesGetResources(ctx context.Context, req ResourcesGetResourcesRequestObject) (ResourcesGetResourcesResponseObject, error) {
	consentID := ctx.Value(api.CtxKeyConsentID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	resources, err := s.service.Resources(ctx, orgID, resource.Filter{ConsentID: consentID}, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseResourceList{
		Data: []struct {
			ResourceID string                         `json:"resourceId"`
			Status     ResponseResourceListDataStatus `json:"status"`
			Type       ResponseResourceListDataType   `json:"type"`
		}{},
		Links: *api.NewPaginatedLinks(s.baseURL+"/resources", resources),
		Meta:  *api.NewPaginatedMeta(resources),
	}
	for _, r := range resources.Records {
		resp.Data = append(resp.Data, struct {
			ResourceID string                         `json:"resourceId"`
			Status     ResponseResourceListDataStatus `json:"status"`
			Type       ResponseResourceListDataType   `json:"type"`
		}{
			ResourceID: r.ResourceID,
			Status:     ResponseResourceListDataStatus(r.Status),
			Type:       ResponseResourceListDataType(r.Type),
		})
	}

	return ResourcesGetResources200JSONResponse{OKResponseResourceListJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	api.WriteError(w, r, err)
}
