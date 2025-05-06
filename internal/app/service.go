package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/luiky/mock-bank/internal/timex"
	"gorm.io/gorm"
)

type Service struct {
	db               *gorm.DB
	directoryService DirectoryService
}

func NewService(db *gorm.DB, directoryService DirectoryService) Service {
	return Service{
		db:               db,
		directoryService: directoryService,
	}
}

func (s Service) createSession(ctx context.Context, idToken string) (*Session, error) {
	idTkn, err := s.directoryService.idToken(ctx, idToken)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Username:      idTkn.Sub,
		Organizations: Organizations{},
		CreatedAt:     timex.Now(),
		ExpiresAt:     timex.Now().Add(sessionValidity),
	}
	for orgID, org := range idTkn.Profile.OrgAccessDetails {
		session.Organizations[orgID] = struct {
			Name string `json:"name"`
		}{
			Name: org.Name,
		}
	}

	if err := s.db.WithContext(ctx).Create(&session).Error; err != nil {
		return nil, fmt.Errorf("could not create session: %w", err)
	}

	return session, nil
}

func (s Service) session(ctx context.Context, id string) (*Session, error) {
	session := &Session{}
	if err := s.db.WithContext(ctx).First(&session, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errSessionNotFound
		}
		return nil, fmt.Errorf("could not fetch session with id %s: %w", id, err)
	}

	if session.IsExpired() {
		_ = s.deleteSession(ctx, id)
		return nil, errSessionNotFound
	}
	return session, nil
}

func (s Service) deleteSession(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Delete(&Session{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("could not delete session with id %s: %w", id, err)
	}
	return nil
}
