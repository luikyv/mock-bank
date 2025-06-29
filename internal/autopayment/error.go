package autopayment

import "github.com/luikyv/mock-bank/internal/errorutil"

var (
	ErrNotFound                   = errorutil.New("resource not found")
	ErrUserDoesntMatchAccount     = errorutil.New("entity does not have access to the specified debtor account")
	ErrClientNotAllowed           = errorutil.New("access is not allowed to client")
	ErrCannotRejectConsent        = errorutil.New("invalid consent status for rejection")
	ErrInvalidConsentStatus       = errorutil.New("invalid consent status")
	ErrConsentPartiallyAccepted   = errorutil.New("consent is in partially accepted status")
	ErrInvalidData                = errorutil.New("invalid data")
	ErrInvalidEndToEndID          = errorutil.New("invalid end to end id")
	ErrPaymentDoesNotMatchConsent = errorutil.New("payment does not match the consent")
	ErrInvalidDate                = errorutil.New("invalid payment date")
	ErrMissingValue               = errorutil.New("parameter is missing")
	ErrCancelNotAllowed           = errorutil.New("cannot cancel the payment")
	ErrRejectionNotAllowed        = errorutil.New("invalid status for rejection")
	ErrInvalidPayment             = errorutil.New("invalid payment")
	ErrInvalidEdition             = errorutil.New("cannot edit the consent")
	ErrFieldNotAllowed            = errorutil.New("field not allowed")
)
