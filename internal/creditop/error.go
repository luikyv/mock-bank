package creditop

import "errors"

var (
	ErrAlreadyExists = errors.New("already exists")
	ErrNotFound      = errors.New("not found")
	ErrNotAllowed    = errors.New("contract not allowed")
)
