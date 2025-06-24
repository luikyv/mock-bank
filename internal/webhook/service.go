package webhook

import (
	"context"
	"github.com/luikyv/go-oidc/pkg/provider"
	"log/slog"
	"net/http"
)

type Service interface {
	Notify(ctx context.Context, clientID, path string)
}

type service struct {
	op *provider.Provider
}

func NewService() *service {
	return &service{}
}

func (s *service) Notify(ctx context.Context, clientID, path string) {
	client, err := s.op.Client(ctx, clientID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get client", "error", err)
		return
	}

	webhookURIs, ok := client.CustomAttribute("webhook_uris").([]string)
	if !ok || len(webhookURIs) == 0 {
		slog.InfoContext(ctx, "client has no webhook URIs")
		return
	}
	webhookURI := webhookURIs[0]

	resp, err := http.Get(webhookURI + path)
	if err != nil {
		slog.ErrorContext(ctx, "failed to notify client", "error", err)
		return
	}
	defer resp.Body.Close()
}

func (s *service) SetOpenIDProvider(op *provider.Provider) {
	s.op = op
}
