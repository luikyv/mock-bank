package opf

import (
	"net/http"

	"github.com/luiky/mock-bank/internal/opf/account"
	accountv2 "github.com/luiky/mock-bank/internal/opf/account/v2"
	"github.com/luiky/mock-bank/internal/opf/consent"
	consentv3 "github.com/luiky/mock-bank/internal/opf/consent/v3"
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
	consentv3.NewServer(s.host, s.consentService, s.op).RegisterRoutes(mux)
	accountv2.NewServer(s.host, s.accountService, s.consentService, s.op).RegisterRoutes(mux)
}
