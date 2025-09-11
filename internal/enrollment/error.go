package enrollment

import "github.com/luikyv/mock-bank/internal/errorutil"

var (
	ErrClientNotAllowed             = errorutil.New("access is not allowed to client")
	ErrNotFound                     = errorutil.New("resource not found")
	ErrUserDoesntMatchAccount       = errorutil.New("entity does not have access to the specified debtor account")
	ErrMissingValue                 = errorutil.New("parameter is missing")
	ErrInvalidData                  = errorutil.New("invalid data")
	ErrInvalidPermissions           = errorutil.New("invalid permissions")
	ErrInvalidPublicKey             = errorutil.New("invalid public key")
	ErrInvalidOrigin                = errorutil.New("invalid origin")
	ErrInvalidRelyingParty          = errorutil.New("invalid relying party")
	ErrInvalidStatus                = errorutil.New("enrollment is not in the expected status")
	ErrInvalidAssertion             = errorutil.New("invalid assertion")
	ErrInvalidChallenge             = errorutil.New("invalid challenge")
	ErrFIDOOptionsAlreadyRegistered = errorutil.New("fido options already registered")
	ErrMissingPermissions           = errorutil.New("missing permissions")
)
