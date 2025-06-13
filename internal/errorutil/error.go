package errorutil

import (
	"errors"
	"fmt"
)

type Error struct {
	error
}

func (e Error) Unwrap() error {
	return e.error
}

func New(msg string) error {
	return Error{
		error: errors.New(msg),
	}
}

func Format(format string, args ...any) error {
	return Error{
		error: fmt.Errorf(format, args...),
	}
}
