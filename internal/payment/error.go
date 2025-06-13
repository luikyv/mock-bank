package payment

import "errors"

var (
	ErrUserNotFound                      = errors.New("user not found")
	ErrAccountNotFound                   = errors.New("account not found")
	ErrNotFound                          = errors.New("consent not found")
	ErrUserDoesntMatchAccount            = errors.New("the logged user does not have access to the specified debtor account")
	ErrClientNotAllowed                  = errors.New("access is not allowed to client")
	ErrConsentAlreadyRejected            = errors.New("the consent is already rejected")
	ErrConsentNotAuthorized              = errors.New("the consent is not authorized")
	ErrInvalidData                       = errors.New("invalid data")
	ErrInvalidEndToEndID                 = errors.New("invalid end to end id")
	ErrCreditorAndDebtorAccountsAreEqual = errors.New("creditor and debtor accounts cannot be equal")
)
