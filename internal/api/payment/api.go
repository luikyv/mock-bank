package payment

import (
	"crypto"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	v4 "github.com/luikyv/mock-bank/internal/api/payment/v4"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
	"github.com/luikyv/mock-bank/internal/payment"
)

type BankConfig interface {
	Host() string
	ISPB() string
	IBGETownCode() string
	AccountBranch() string
}

type Server struct {
	config             BankConfig
	service            payment.Service
	idempotencyService idempotency.Service
	jwtService         jwtutil.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	config BankConfig,
	service payment.Service,
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
		idempotencyService: idempotencyService,
		jwtService:         jwtService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	muxV4, versionV4 := v4.NewServer(s.config, s.service, s.idempotencyService, s.jwtService, s.op, s.keystoreHost, s.orgID, s.signer).Handler()

	mux.Handle("/open-banking/payments/", middleware.VersionRouting(muxV4, map[string]http.Handler{
		versionV4: muxV4,
	}))
}
