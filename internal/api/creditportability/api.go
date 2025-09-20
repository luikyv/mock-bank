package creditportability

import (
	"crypto"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	v1 "github.com/luikyv/mock-bank/internal/api/creditportability/v1"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/creditportability"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
)

type BankConfig interface {
	Host() string
	Brand() string
	CNPJ() string
	ISPB() string
	AccountBranch() string
}

type Server struct {
	config             BankConfig
	service            creditportability.Service
	consentService     consent.Service
	idempotencyService idempotency.Service
	jwtService         jwtutil.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	config BankConfig,
	service creditportability.Service,
	consentService consent.Service,
	idempotencyService idempotency.Service,
	jwtService jwtutil.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		config:             config,
		service:            service,
		consentService:     consentService,
		idempotencyService: idempotencyService,
		jwtService:         jwtService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	muxV1, versionV1 := v1.NewServer(s.config, s.service, s.consentService, s.idempotencyService, s.jwtService, s.op, s.orgID, s.keystoreHost, s.signer).Handler()

	mux.Handle("/open-banking/credit-portability/", middleware.VersionRouting(muxV1, map[string]http.Handler{
		versionV1: muxV1,
	}))
}
