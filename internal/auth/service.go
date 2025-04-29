package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/timex"
)

type Service struct {
	st               Storage
	directoryService DirectoryService
}

func NewService(st Storage, directoryService DirectoryService) Service {
	return Service{
		st:               st,
		directoryService: directoryService,
	}
}

func (s Service) createSession(ctx context.Context, idToken string) (Session, error) {
	idTkn, err := s.directoryService.idToken(ctx, idToken)
	if err != nil {
		return Session{}, err
	}

	session := Session{
		ID:            uuid.NewString(),
		Username:      idTkn.Sub,
		Organizations: map[string]Organization{},
		CreatedAt:     timex.DateTimeNow(),
		ExpiresAt:     timex.DateTimeNow(),
	}
	for orgID, org := range idTkn.Profile.OrgAccessDetails {
		session.Organizations[orgID] = Organization{
			Name: org.Name,
		}
	}
	if err := s.st.createSession(ctx, session); err != nil {
		return Session{}, err
	}

	return session, nil
}

func (s Service) session(ctx context.Context, id string) (Session, error) {
	session, err := s.st.session(ctx, id)
	if err != nil {
		return Session{}, err
	}

	if session.IsExpired() {
		_ = s.deleteSession(ctx, id)
		return Session{}, errNotFound
	}
	return session, nil
}

func (s Service) deleteSession(ctx context.Context, id string) error {
	return s.st.deleteSession(ctx, id)
}
