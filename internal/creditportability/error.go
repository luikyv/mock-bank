package creditportability

import "errors"

var (
	ErrNotFound         = errors.New("portability not found")
	ErrClientNotAllowed = errors.New("access is not allowed to client")
)
