package consent

import (
	"context"
	"errors"
	"log/slog"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luiky/mock-bank/internal/user"
)

var (
	errNotFound                               = errors.New("consent not found")
	errAccessNotAllowed                       = errors.New("access to consent is not allowed")
	errInvalidPermissionGroup                 = errors.New("the requested permission groups are invalid")
	errInvalidExpiration                      = errors.New("the expiration date time is invalid")
	errPersonalAndBusinessPermissionsTogether = errors.New("cannot request personal and business permissions together")
	errAlreadyRejected                        = errors.New("the consent is already rejected")
	errExtensionNotAllowed                    = errors.New("the consent is not allowed to be extended")
	errCannotExtendConsentNotAuthorized       = errors.New("the consent is not in the AUTHORISED status")
	errCannotExtendConsentForJointAccount     = errors.New("a consent created for a joint account cannot be extended")
)

type Service struct {
	st          Storage
	userService user.Service
}

func NewService(st Storage, userService user.Service) Service {
	return Service{
		st:          st,
		userService: userService,
	}
}

func (s Service) Authorize(ctx context.Context, c Consent) error {

	if !c.IsAwaitingAuthorization() {
		return errors.New("consent is not in the AWAITING_AUTHORIZATION status")
	}

	c.Status = StatusAuthorized
	c.StatusUpdatedAt = timex.Now()
	return s.st.save(ctx, c)
}

func (s Service) Consent(ctx context.Context, id string) (Consent, error) {
	c, err := s.st.consent(ctx, id)
	if err != nil {
		return Consent{}, err
	}

	if ctx.Value(api.CtxKeyClientID) != nil && ctx.Value(api.CtxKeyClientID) != c.ClientID {
		return Consent{}, errAccessNotAllowed
	}

	if err := s.modify(ctx, c); err != nil {
		return Consent{}, err
	}

	return c, nil
}

func (s Service) Reject(ctx context.Context, id string, by RejectedBy, reason RejectionReason) error {
	c, err := s.Consent(ctx, id)
	if err != nil {
		return err
	}
	if c.Status == StatusRejected {
		return errAlreadyRejected
	}

	c.Status = StatusRejected
	c.StatusUpdatedAt = timex.Now()
	c.RejectedBy = by
	c.RejectionReason = reason
	return s.st.save(ctx, c)
}

func (s Service) delete(ctx context.Context, id string) error {
	c, err := s.Consent(ctx, id)
	if err != nil {
		return err
	}

	rejectedBy := RejectedByUser
	rejectionReason := RejectionReasonCustomerManuallyRejected
	if c.IsAuthorized() {
		rejectionReason = RejectionReasonCustomerManuallyRevoked
	}

	return s.Reject(ctx, id, rejectedBy, rejectionReason)
}

func (s Service) create(ctx context.Context, c Consent) error {
	if err := validate(c); err != nil {
		return err
	}

	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	if user, err := s.userService.UserByCPF(ctx, c.UserCPF, orgID); err == nil {
		c.UserID = user.ID
	}

	return s.st.save(ctx, c)
}

// modify will evaluated the consent information and modify it to be compliant.
func (s Service) modify(ctx context.Context, consent Consent) error {
	consentWasModified := false

	if consent.HasAuthExpired() {
		slog.DebugContext(ctx, "consent awaiting authorization for too long, moving to rejected")
		consent.Status = StatusRejected
		consent.RejectedBy = RejectedByUser
		consent.RejectionReason = RejectionReasonConsentExpired
		consent.StatusUpdatedAt = timex.Now()
		consentWasModified = true
	}

	if consent.IsExpired() {
		slog.DebugContext(ctx, "consent reached expiration, moving to rejected")
		consent.Status = StatusRejected
		consent.RejectedBy = RejectedByASPSP
		consent.RejectionReason = RejectionReasonConsentMaxDateReached
		consent.StatusUpdatedAt = timex.Now()
		consentWasModified = true
	}

	if consentWasModified {
		slog.DebugContext(ctx, "the consent was modified")
		if err := s.st.save(ctx, consent); err != nil {
			return err
		}
	}

	return nil
}

func (s Service) extend(ctx context.Context, id string, ext Extension) (Consent, error) {
	c, err := s.Consent(ctx, id)
	if err != nil {
		return Consent{}, err
	}

	if err := validateExtension(c, ext); err != nil {
		return Consent{}, err
	}

	ext.PreviousExpiresAt = c.ExpiresAt
	c.ExpiresAt = ext.ExpiresAt
	c.Extensions = append([]Extension{ext}, c.Extensions...)
	if err := s.st.save(ctx, c); err != nil {
		return Consent{}, err
	}

	return c, nil
}

func (s Service) extensions(ctx context.Context, id string, pag page.Pagination) (page.Page[Extension], error) {
	return s.st.extensions(ctx, id, pag)
}

func (s Service) consents(ctx context.Context, userID, orgID string, pag page.Pagination) (page.Page[Consent], error) {
	return s.st.consents(ctx, userID, orgID, pag)
}

func validate(c Consent) error {
	if err := validatePermissions(c.Permissions); err != nil {
		return err
	}

	now := timex.Now()
	if c.ExpiresAt != nil && c.ExpiresAt.After(now.AddDate(1, 0, 0)) {
		return errInvalidExpiration
	}

	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return errInvalidExpiration
	}

	return nil
}
