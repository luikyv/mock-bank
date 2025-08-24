package consent

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	v3 "github.com/luikyv/mock-bank/internal/api/resource/v3"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/resource"
)

type BankConfig interface {
	Host() string
}

type Server struct {
	config         BankConfig
	service        resource.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(config BankConfig, service resource.Service, consentService consent.Service, op *provider.Provider) Server {
	return Server{
		config:         config,
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	muxV3, versionV3 := v3.NewServer(s.config.Host(), s.service, s.consentService, s.op).Handler()

	mux.Handle("/open-banking/resources/", middleware.VersionRouting(muxV3, map[string]http.Handler{
		versionV3: muxV3,
	}))
}
