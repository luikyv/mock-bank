package consent

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	v3 "github.com/luikyv/mock-bank/internal/api/consent/v3"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
)

type BankConfig interface {
	Host() string
}

type Server struct {
	config  BankConfig
	service consent.Service
	op      *provider.Provider
}

func NewServer(config BankConfig, service consent.Service, op *provider.Provider) Server {
	return Server{
		config:  config,
		service: service,
		op:      op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	muxV3, versionV3 := v3.NewServer(s.config.Host(), s.service, s.op).Handler()

	mux.Handle("/open-banking/consents/", middleware.VersionRouting(muxV3, map[string]http.Handler{
		versionV3: muxV3,
	}))
}
