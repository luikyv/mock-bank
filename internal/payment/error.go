package payment

import "github.com/luikyv/mock-bank/internal/errorutil"

var (
	ErrUserNotFound                      = errorutil.New("user not found")
	ErrAccountNotFound                   = errorutil.New("account not found")
	ErrNotFound                          = errorutil.New("consent not found")
	ErrUserDoesntMatchAccount            = errorutil.New("the logged user does not have access to the specified debtor account")
	ErrClientNotAllowed                  = errorutil.New("access is not allowed to client")
	ErrConsentAlreadyRejected            = errorutil.New("the consent is already rejected")
	ErrConsentNotAuthorized              = errorutil.New("the consent is not authorized")
	ErrInvalidData                       = errorutil.New("invalid data")
	ErrInvalidEndToEndID                 = errorutil.New("invalid end to end id")
	ErrCreditorAndDebtorAccountsAreEqual = errorutil.New("creditor and debtor accounts cannot be equal")
	ErrPaymentDoesNotMatchConsent        = errorutil.New("payment does not match the consent")
	ErrInvalidDate                       = errorutil.New("invalid payment date")
	ErrMissingValue                      = errorutil.New("parameter is missing")
	ErrCancelNotAllowed                  = errorutil.New("cannot cancel the payment")
	ErrInvalidPayment                    = errorutil.New("invalid payment")
)
