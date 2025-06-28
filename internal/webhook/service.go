package webhook

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/luikyv/mock-bank/internal/client"
)

type Service struct {
	clientService client.Service
}

func NewService(clientService client.Service) Service {
	return Service{clientService: clientService}
}

func (s Service) Notify(ctx context.Context, clientID, path string) {
	slog.DebugContext(ctx, "notifying client", "client_id", clientID, "path", path)

	client, err := s.clientService.Client(ctx, clientID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get client", "error", err)
		return
	}

	if len(client.WebhookURIs) == 0 {
		slog.DebugContext(ctx, "client has no webhook uris")
		return
	}
	webhookURI := client.WebhookURIs[0]

	resp, err := http.Get(webhookURI + path)
	if err != nil {
		slog.ErrorContext(ctx, "failed to notify client", "error", err)
		return
	}
	defer resp.Body.Close()

	slog.DebugContext(ctx, "client was notified", "status", resp.Status)
}
