package idempotency

import "errors"

var (
	ErrNotFound = errors.New("idempotency record not found")
)
