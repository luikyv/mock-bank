package user

import "errors"

var (
	ErrNotFound               = errors.New("entity not found")
	ErrAlreadyExists          = errors.New("entity already exists")
	ErrUserDoesNotOwnBusiness = errors.New("user is not associated with the business")
	ErrInvalidOrgID           = errors.New("invalid org id")
)
