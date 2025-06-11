package payment

import "errors"

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrAccountNotFound        = errors.New("account not found")
	ErrConsentNotFound        = errors.New("consent not found")
	ErrUserDoesntMatchAccount = errors.New("the logged user does not have access to the specified debtor account")
	ErrAccessNotAllowed       = errors.New("access to consent is not allowed")
)
