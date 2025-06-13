package consent

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/errorutil"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"gorm.io/gorm"
)

type Service struct {
	db          *gorm.DB
	userService user.Service
}

func NewService(db *gorm.DB, userService user.Service) Service {
	return Service{
		db:          db,
		userService: userService,
	}
}

func (s Service) Authorize(ctx context.Context, c *Consent) error {

	if !c.IsAwaitingAuthorization() {
		return errorutil.New("consent is not in the awaiting authorization status")
	}

	c.Status = StatusAuthorized
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	c.UpdatedAt = timeutil.DateTimeNow()
	return s.save(ctx, c)
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

	if err := s.modify(ctx, c); err != nil {
		return nil, err
	}

	return c, nil
}

func (s Service) Reject(ctx context.Context, id, orgID string, by RejectedBy, reason RejectionReason) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	return s.reject(ctx, c, by, reason)
}

func (s Service) reject(ctx context.Context, c *Consent, by RejectedBy, reason RejectionReason) error {
	if c.Status == StatusRejected {
		return ErrAlreadyRejected
	}

	c.Status = StatusRejected
	c.StatusUpdatedAt = timeutil.DateTimeNow()
	c.UpdatedAt = timeutil.DateTimeNow()
	c.RejectedBy = by
	c.RejectionReason = reason
	return s.save(ctx, c)
}

func (s Service) Delete(ctx context.Context, id, orgID string) error {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return err
	}

	rejectedBy := RejectedByUser
	rejectionReason := RejectionReasonCustomerManuallyRejected
	if c.IsAuthorized() {
		rejectionReason = RejectionReasonCustomerManuallyRevoked
	}

	return s.Reject(ctx, id, orgID, rejectedBy, rejectionReason)
}

func (s Service) Create(ctx context.Context, c *Consent) error {
	if err := s.validate(ctx, c); err != nil {
		return err
	}

	if user, err := s.userService.UserByCPF(ctx, c.UserCPF, c.OrgID); err == nil {
		c.UserID = &user.ID
	}

	return s.db.WithContext(ctx).Create(c).Error
}

// modify will evaluated the consent information and modify it to be compliant.
func (s Service) modify(ctx context.Context, c *Consent) error {
	if c.HasAuthExpired() {
		slog.DebugContext(ctx, "consent awaiting authorization for too long, moving to rejected")
		return s.reject(ctx, c, RejectedByUser, RejectionReasonConsentExpired)
	}

	if c.IsExpired() {
		slog.DebugContext(ctx, "consent reached expiration, moving to rejected")
		return s.reject(ctx, c, RejectedByASPSP, RejectionReasonConsentMaxDateReached)
	}

	return nil
}

func (s Service) Extend(ctx context.Context, id, orgID string, ext *Extension) (*Consent, error) {
	c, err := s.Consent(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	if err := validateExtension(c, ext); err != nil {
		return nil, err
	}

	c.ExpiresAt = ext.ExpiresAt
	if err := s.save(ctx, c); err != nil {
		return nil, err
	}

	ext.PreviousExpiresAt = c.ExpiresAt
	if err := s.saveExtension(ctx, ext); err != nil {
		return nil, err
	}

	return c, nil
}

func (s Service) validate(ctx context.Context, c *Consent) error {
	if err := validatePermissions(c.Permissions); err != nil {
		return err
	}

	now := timeutil.Now()
	if c.ExpiresAt != nil && (c.ExpiresAt.After(now.AddDate(1, 0, 0)) || c.ExpiresAt.Before(now)) {
		return ErrInvalidExpiration
	}

	return nil
}

func (s Service) save(ctx context.Context, c *Consent) error {
	return s.db.WithContext(ctx).Save(c).Error
}

func (s Service) Consents(ctx context.Context, userID uuid.UUID, orgID string, pag page.Pagination) (page.Page[*Consent], error) {
	query := s.db.WithContext(ctx).Model(&Consent{}).Where("user_id = ? AND org_id = ?", userID, orgID)

	var consents []*Consent
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&consents).Error; err != nil {
		return page.Page[*Consent]{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Consent]{}, err
	}

	for _, c := range consents {
		if err := s.modify(ctx, c); err != nil {
			return page.Page[*Consent]{}, err
		}
	}

	return page.New(consents, pag, int(total)), nil
}

func (s Service) saveExtension(ctx context.Context, ext *Extension) error {
	return s.db.WithContext(ctx).Save(ext).Error
}

func (s Service) Extensions(ctx context.Context, consentURN, orgID string, pag page.Pagination) (page.Page[*Extension], error) {
	consentID := strings.TrimPrefix(consentURN, URNPrefix)
	query := s.db.WithContext(ctx).Model(&Extension{}).Where("consent_id = ? AND org_id = ?", consentID, orgID)

	var extensions []*Extension
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Order("created_at DESC").
		Find(&extensions).Error; err != nil {
		return page.Page[*Extension]{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return page.Page[*Extension]{}, err
	}

	return page.New(extensions, pag, int(total)), nil
}
