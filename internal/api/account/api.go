package account

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/account"
	v2 "github.com/luikyv/mock-bank/internal/api/account/v2"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
)

type Server struct {
	host           string
	service        account.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(host string, service account.Service, consentService consent.Service, op *provider.Provider) Server {
	return Server{
		host:           host,
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	muxV2, versionV2 := v2.NewServer(s.host, s.service, s.consentService, s.op).Handler()

	mux.Handle("/open-banking/accounts/", middleware.VersionRouting(muxV2, map[string]http.Handler{
		versionV2: muxV2,
	}))
}
