package autopayment

import (
	"crypto"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/provider"
	v2 "github.com/luikyv/mock-bank/internal/api/autopayment/v2"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
)

type BankConfig interface {
	Host() string
	ISPB() string
	IBGETownCode() string
	AccountBranch() string
}

type Server struct {
	config             BankConfig
	service            autopayment.Service
	idempotencyService idempotency.Service
	jwtService         jwtutil.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	config BankConfig,
	service autopayment.Service,
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
	muxV2, versionV2 := v2.NewServer(s.config, s.service, s.idempotencyService, s.jwtService, s.op, s.keystoreHost, s.orgID, s.signer).Handler()

	mux.Handle("/open-banking/automatic-payments/", middleware.VersionRouting(muxV2, map[string]http.Handler{
		versionV2: muxV2,
	}))
}
