package session

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

type Service struct {
	db                   *gorm.DB
	directoryIssuer      string
	directoryClientID    string
	directoryRedirectURI string
	directoryJWTSigner   crypto.Signer
	directoryMTLSClient  *http.Client
}

func NewService(db *gorm.DB, issuer, clientID, redirectURI string, jwtSigner crypto.Signer, mtlsClient *http.Client) Service {
	return Service{
		db:                   db,
		directoryIssuer:      issuer,
		directoryClientID:    clientID,
		directoryRedirectURI: redirectURI,
		directoryJWTSigner:   jwtSigner,
		directoryMTLSClient:  mtlsClient,
	}
}

func (s Service) Create(ctx context.Context) (session *Session, authURL string, err error) {
	authURL, codeVerifier, err := s.AuthURL(ctx)
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

func (s Service) Authorize(ctx context.Context, sessionID, authCode string) error {
	var session Session
	if err := s.db.WithContext(ctx).First(&session, "id = ?", sessionID).Error; err != nil {
		return fmt.Errorf("could not find session: %w", err)
	}

	idTkn, err := s.IDToken(ctx, authCode, session.CodeVerifier)
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

	if err := s.db.WithContext(ctx).
		Model(&Session{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ?", sessionID).
		Updates(&session).Error; err != nil {
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
		_ = s.Delete(ctx, id)
		return nil, ErrNotFound
	}
	return session, nil
}

func (s Service) Delete(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Delete(&Session{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("could not delete session with id %s: %w", id, err)
	}
	return nil
}
