//go:generate oapi-codegen -config=./config.yml -package=creditportabilityv1 -o=./api_gen.go ./swagger.yml
package creditportabilityv1

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/creditportability"
)

var _ StrictServerInterface = Server{}

type BankConfig interface {
	Host() string
	Brand() string
	CNPJ() string
	ISPB() string
}

type Server struct {
	config         BankConfig
	baseURL        string
	service        *creditportability.Service
	consentService consent.Service
	op             *provider.Provider
}

func NewServer(service *creditportability.Service) *Server {
	return &Server{service: service}
}

func (s Server) CreditPortabilityGetCreditOperationsContratIDPortabilityEligibility(ctx context.Context, request CreditPortabilityGetCreditOperationsContratIDPortabilityEligibilityRequestObject) (CreditPortabilityGetCreditOperationsContratIDPortabilityEligibilityResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityPostPortabilities(ctx context.Context, request CreditPortabilityPostPortabilitiesRequestObject) (CreditPortabilityPostPortabilitiesResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityGetPortabilitiesByPortabilityID(ctx context.Context, request CreditPortabilityGetPortabilitiesByPortabilityIDRequestObject) (CreditPortabilityGetPortabilitiesByPortabilityIDResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityGetAccountData(ctx context.Context, request CreditPortabilityGetAccountDataRequestObject) (CreditPortabilityGetAccountDataResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityPatchPortabilitiesPortabilityIDCancel(ctx context.Context, request CreditPortabilityPatchPortabilitiesPortabilityIDCancelRequestObject) (CreditPortabilityPatchPortabilitiesPortabilityIDCancelResponseObject, error) {
	return nil, nil
}

func (s Server) CreditPortabilityPostPortabilitiesPortabilityIDPayment(ctx context.Context, request CreditPortabilityPostPortabilitiesPortabilityIDPaymentRequestObject) (CreditPortabilityPostPortabilitiesPortabilityIDPaymentResponseObject, error) {
	return nil, nil
}
