package account

import "errors"

var (
	ErrAlreadyExists                    = errors.New("account already exists")
	ErrNotFound                         = errors.New("account not found")
	errNotAllowed                       = errors.New("account not allowed")
	errJointAccountPendingAuthorization = errors.New("the account was not authorized by all users")
)
