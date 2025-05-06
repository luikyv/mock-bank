package opf

import (
	"net/http"

	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luikyv/go-oidc/pkg/provider"
)

type Server struct {
	host           string
	consentService consent.Service
	accountService account.Service
	op             *provider.Provider
}

func NewServer(
	host string,
	consentService consent.Service,
	accountService account.Service,
	op *provider.Provider,
) Server {
	return Server{
		host:           host,
		consentService: consentService,
		accountService: accountService,
		op:             op,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	s.op.RegisterRoutes(mux)
	consent.NewServerV3(s.host, s.consentService, s.op).Register(mux)
	account.NewServerV2(s.host, s.accountService, s.consentService, s.op).Register(mux)
}
