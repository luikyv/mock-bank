package account

import "errors"

var (
	ErrAlreadyExists                    = errors.New("account already exists")
	ErrNotFound                         = errors.New("account not found")
	ErrNotAllowed                       = errors.New("account not allowed")
	ErrJointAccountPendingAuthorization = errors.New("the account was not authorized by all users")
)
