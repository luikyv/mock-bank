package consent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"gorm.io/gorm"
)

type Service struct {
	db              *gorm.DB
	userService     user.Service
	resourceService resource.Service
}

func NewService(db *gorm.DB, userService user.Service, resourceService resource.Service) Service {
	return Service{
		db:              db,
		userService:     userService,
		resourceService: resourceService,
	}
}

func (s Service) Create(ctx context.Context, c *Consent) error {
	c.Status = StatusAwaitingAuthorization
	now := timeutil.DateTimeNow()
	c.StatusUpdatedAt = now
	c.CreatedAt = now
	c.UpdatedAt = now

	if err := s.validate(ctx, c); err != nil {
		return err
	}

	if u, err := s.userService.User(ctx, user.Query{CPF: c.UserIdentification}, c.OrgID); err == nil {
		c.OwnerID = &u.ID
	}

	if c.BusinessIdentification != nil {
		if u, err := s.userService.User(ctx, user.Query{CNPJ: *c.BusinessIdentification}, c.OrgID); err == nil {
			c.OwnerID = &u.ID
		}
	}

	return s.db.WithContext(ctx).Create(c).Error
}

func (s Service) Authorize(ctx context.Context, c *Consent) error {
	if c.Status != StatusAwaitingAuthorization {
		return errorutil.New("consent is not in the awaiting authorization status")
	}

	return s.updateStatus(ctx, c, StatusAuthorized)
}

func (s Service) Consent(ctx context.Context, id, orgID string) (*Consent, error) {
	id = strings.TrimPrefix(id, URNPrefix)
	c := &Consent{}
	if err := s.db.WithContext(ctx).Where("id = ? AND org_id = ?", id, orgID).First(c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != c.ClientID {
		return nil, ErrAccessNotAllowed
	}

	return c, s.runAutomations(ctx, c)
}

func (s Service) Consents(ctx context.Context, ownerID uuid.UUID, orgID string, pag page.Pagination) (page.Page[*Consent], error) {
	query := s.db.WithContext(ctx).Model(&Consent{}).Where("owner_id = ? AND org_id = ?", ownerID, orgID).Order("created_at DESC")

	consents, err := page.Paginate[*Consent](query, pag)
	if err != nil {
		return page.Page[*Consent]{}, err
	}

	for _, c := range consents.Records {
		if err := s.runAutomations(ctx, c); err != nil {
			return page.Page[*Consent]{}, err
		}
	}

	return consents, nil
}

func (s Service) Reject(ctx context.Context, id, orgID string, by RejectedBy, reason RejectionReason) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	return s.reject(ctx, c, by, reason)
}

func (s Service) Delete(ctx context.Context, id, orgID string) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	rejectedBy := RejectedByUser
	rejectionReason := RejectionReasonCustomerManuallyRejected
	if c.Status == StatusAuthorized {
		rejectionReason = RejectionReasonCustomerManuallyRevoked
	}

	return s.Reject(ctx, id, orgID, rejectedBy, rejectionReason)
}

func (s Service) Extend(ctx context.Context, id, orgID string, ext *Extension) (*Consent, error) {
	ext.ConsentID = uuid.MustParse(id)
	ext.OrgID = orgID
	ext.RequestedAt = timeutil.DateTimeNow()
	ext.CreatedAt = timeutil.DateTimeNow()
	ext.UpdatedAt = timeutil.DateTimeNow()

	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if c.Status != StatusAuthorized {
		return nil, ErrCannotExtendConsentNotAuthorized
	}

	if c.UserIdentification != ext.UserIdentification {
		return nil, ErrExtensionNotAllowed
	}

	if c.BusinessIdentification != nil && reflect.DeepEqual(c.BusinessIdentification, ext.BusinessIdentification) {
		return nil, ErrExtensionNotAllowed
	}

	rs, err := s.resourceService.Resources(ctx, c.OrgID, resource.Filter{
		ConsentID: c.ID.String(),
		Status:    resource.StatusPendingAuthorization,
	}, page.NewPagination(nil, nil))
	if err != nil {
		return nil, errorutil.Format("failed to get resources pending authorization: %w", err)
	}
	if rs.TotalRecords != 0 {
		return nil, ErrCannotExtendConsentPendingAuthorization
	}

	if ext.ExpiresAt != nil {
		now := timeutil.DateTimeNow()
		if ext.ExpiresAt.Before(now) || ext.ExpiresAt.After(now.AddDate(1, 0, 0)) {
			return nil, ErrInvalidExpiration
		}

		if c.ExpiresAt != nil && !ext.ExpiresAt.After(*c.ExpiresAt) {
			return nil, ErrInvalidExpiration
		}
	}

	c.ExpiresAt = ext.ExpiresAt
	if err := s.update(ctx, c); err != nil {
		return nil, err
	}

	ext.PreviousExpiresAt = c.ExpiresAt
	return c, s.db.WithContext(ctx).Create(ext).Error
}

func (s Service) Extensions(ctx context.Context, consentURN, orgID string, pag page.Pagination) (page.Page[*Extension], error) {
	consentID := strings.TrimPrefix(consentURN, URNPrefix)
	query := s.db.WithContext(ctx).Model(&Extension{}).Where("consent_id = ? AND org_id = ?", consentID, orgID).Order("created_at DESC")

	extensions, err := page.Paginate[*Extension](query, pag)
	if err != nil {
		return page.Page[*Extension]{}, fmt.Errorf("could not find extensions: %w", err)
	}

	return extensions, nil
}

func (s Service) validate(_ context.Context, c *Consent) error {
	if err := validatePermissions(c.Permissions); err != nil {
		return err
	}

	now := timeutil.DateTimeNow()
	if c.ExpiresAt != nil && (c.ExpiresAt.After(now.AddDate(1, 0, 0)) || c.ExpiresAt.Before(now)) {
		return ErrInvalidExpiration
	}

	return nil
}

func (s Service) runAutomations(ctx context.Context, c *Consent) error {
	switch c.Status {
	case StatusAwaitingAuthorization:
		if timeutil.DateTimeNow().After(c.CreatedAt.Add(3600 * time.Second)) {
			slog.DebugContext(ctx, "consent awaiting authorization for too long, moving to rejected")
			return s.reject(ctx, c, RejectedByUser, RejectionReasonConsentExpired)
		}
	case StatusAuthorized:
		if c.ExpiresAt != nil && timeutil.DateTimeNow().After(*c.ExpiresAt) {
			slog.DebugContext(ctx, "consent reached expiration, moving to rejected")
			return s.reject(ctx, c, RejectedByASPSP, RejectionReasonConsentMaxDateReached)
		}
	}

	return nil
}

func (s Service) reject(ctx context.Context, c *Consent, by RejectedBy, reason RejectionReason) error {
	if c.Status == StatusRejected {
		return ErrAlreadyRejected
	}

	c.Rejection = &Rejection{
		By:     by,
		Reason: reason,
	}
	return s.updateStatus(ctx, c, StatusRejected)
}

func (s Service) updateStatus(ctx context.Context, c *Consent, status Status) error {
	c.Status = status
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	return s.update(ctx, c)
}

func (s Service) update(ctx context.Context, c *Consent) error {
	c.UpdatedAt = timeutil.DateTimeNow()
	return s.db.WithContext(ctx).
		Model(&Consent{}).
		Omit("ID", "CreatedAt", "OrgID").
		Where("id = ? AND org_id = ?", c.ID, c.OrgID).
		Updates(c).Error
}
