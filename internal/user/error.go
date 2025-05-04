package user

import "errors"

var (
	ErrAlreadyExists = errors.New("user already exists")
)
