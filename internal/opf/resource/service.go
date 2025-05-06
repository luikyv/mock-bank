package resource

import "context"

type Service struct {
}

func (Service) IsAvailable(ctx context.Context, resourceID, consentID string) bool {
	return false
}
