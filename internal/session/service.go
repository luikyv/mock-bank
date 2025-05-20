package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luiky/mock-bank/internal/directory"
	"github.com/luiky/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db               *gorm.DB
	directoryService directory.Service
}

func NewService(db *gorm.DB, directoryService directory.Service) Service {
	return Service{
		db:               db,
		directoryService: directoryService,
	}
}

func (s Service) CreateSession(ctx context.Context, idToken, nonceHash string) (*Session, error) {
	idTkn, err := s.directoryService.IDToken(ctx, idToken, nonceHash)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Username:      idTkn.Sub,
		Organizations: Organizations{},
		CreatedAt:     timeutil.Now(),
		ExpiresAt:     timeutil.Now().Add(1 * time.Hour),
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

func (s Service) Session(ctx context.Context, id string) (*Session, error) {
	session := &Session{}
	if err := s.db.WithContext(ctx).First(&session, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("could not fetch session with id %s: %w", id, err)
	}

	if session.IsExpired() {
		_ = s.DeleteSession(ctx, id)
		return nil, ErrNotFound
	}
	return session, nil
}

func (s Service) DeleteSession(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Delete(&Session{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("could not delete session with id %s: %w", id, err)
	}
	return nil
}
