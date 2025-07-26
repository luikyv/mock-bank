package account

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/account"
	v2 "github.com/luikyv/mock-bank/internal/api/account/v2"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
)

type BankConfig interface {
	Host() string
	Brand() string
	CNPJ() string
	ISPB() string
	IBGETownCode() string
	Currency() string
	AccountCompeCode() string
	AccountBranch() string
	AccountCheckDigit() string
}

type Server struct {
	config         BankConfig
	service        account.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(config BankConfig, service account.Service, consentService consent.Service, op *provider.Provider) Server {
	return Server{
		config:         config,
		service:        service,
		consentService: consentService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	muxV2, versionV2 := v2.NewServer(s.config, s.service, s.consentService, s.op).Handler()

	mux.Handle("/open-banking/accounts/", middleware.VersionRouting(muxV2, map[string]http.Handler{
		versionV2: muxV2,
	}))
}
