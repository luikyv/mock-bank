package consent

import "errors"

var (
	ErrNotFound                                = errors.New("consent not found")
	ErrAccessNotAllowed                        = errors.New("access to consent is not allowed")
	ErrInvalidPermissionGroup                  = errors.New("the requested permission groups are invalid")
	ErrInvalidExpiration                       = errors.New("the expiration date time is invalid")
	ErrPersonalAndBusinessPermissionsTogether  = errors.New("cannot request personal and business permissions together")
	ErrAlreadyRejected                         = errors.New("the consent is already rejected")
	ErrExtensionNotAllowed                     = errors.New("the consent is not allowed to be extended")
	ErrCannotExtendConsentNotAuthorized        = errors.New("the consent is not in the AUTHORISED status")
	ErrCannotExtendConsentPendingAuthorization = errors.New("cannot extend consent with resourcespending authorization")
)
