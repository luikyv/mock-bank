package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luikyv/mock-bank/internal/directory"
	"github.com/luikyv/mock-bank/internal/timeutil"
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

func (s Service) CreateSession(ctx context.Context) (session *Session, authURL string, err error) {
	authURL, codeVerifier, err := s.directoryService.AuthURL(ctx)
	if err != nil {
		return nil, "", err
	}

	session = &Session{
		CodeVerifier: codeVerifier,
		ExpiresAt:    timeutil.DateTimeNow().Add(10 * time.Minute),
	}
	if err := s.db.WithContext(ctx).Create(&session).Error; err != nil {
		return nil, "", fmt.Errorf("could not create session: %w", err)
	}

	return session, authURL, nil
}

func (s Service) AuthorizeSession(ctx context.Context, sessionID, authCode string) error {
	var session Session
	if err := s.db.WithContext(ctx).First(&session, "id = ?", sessionID).Error; err != nil {
		return fmt.Errorf("could not find session: %w", err)
	}

	idTkn, err := s.directoryService.IDToken(ctx, authCode, session.CodeVerifier)
	if err != nil {
		return err
	}

	session.Username = idTkn.Sub
	session.ExpiresAt = session.CreatedAt.Add(1 * time.Hour)
	session.CodeVerifier = ""
	session.Organizations = Organizations{}
	for orgID, org := range idTkn.Profile.OrgAccessDetails {
		session.Organizations[orgID] = struct {
			Name string `json:"name"`
		}{
			Name: org.Name,
		}
	}

	if err := s.db.WithContext(ctx).Save(&session).Error; err != nil {
		return fmt.Errorf("could not authorize session: %w", err)
	}

	return nil
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
