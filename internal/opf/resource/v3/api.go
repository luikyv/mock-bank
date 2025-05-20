package v3

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/luiky/mock-bank/internal/apiutil"
	"github.com/luiky/mock-bank/internal/opf"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/middleware"
	"github.com/luiky/mock-bank/internal/opf/resource"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	netmiddleware "github.com/oapi-codegen/nethttp-middleware"
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

	spec, err := GetSwagger()
	if err != nil {
		panic(err)
	}
	spec.Servers = nil
	swaggerMiddleware := netmiddleware.OapiRequestValidatorWithOptions(spec, &netmiddleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
		ErrorHandler: func(w http.ResponseWriter, message string, _ int) {
			apiutil.WriteError(w, apiutil.NewError("INVALID_REQUEST", http.StatusBadRequest, message))
		},
	})

	strictHandler := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeResponseError(w, err)
		},
	})
	wrapper := ServerInterfaceWrapper{
		Handler:            strictHandler,
		HandlerMiddlewares: []MiddlewareFunc{swaggerMiddleware, middleware.FAPIID(nil)},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			apiutil.WriteError(w, apiutil.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.ResourcesGetResources)
	handler = consent.PermissionMiddleware(handler, s.consentService, consent.PermissionResourcesRead)
	handler = middleware.AuthHandler(handler, s.op, goidc.ScopeOpenID, consent.ScopeID)
	resourceMux.Handle("GET /resources", handler)

	mux.Handle("/open-banking/resources/v3/", http.StripPrefix("/open-banking/resources/v3", resourceMux))
}

func (s Server) ResourcesGetResources(ctx context.Context, req ResourcesGetResourcesRequestObject) (ResourcesGetResourcesResponseObject, error) {
	consentID := ctx.Value(opf.CtxKeyConsentID).(string)
	orgID := ctx.Value(opf.CtxKeyOrgID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	resources, err := s.service.ConsentedResources(ctx, consentID, orgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponseResourceList{
		Data: []struct {
			ResourceID string                         `json:"resourceId"`
			Status     ResponseResourceListDataStatus `json:"status"`
			Type       ResponseResourceListDataType   `json:"type"`
		}{},
		Links: *apiutil.NewPaginatedLinks(s.baseURL+"/resources", resources),
		Meta:  *apiutil.NewPaginatedMeta(resources),
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

func writeResponseError(w http.ResponseWriter, err error) {
	apiutil.WriteError(w, err)
}
