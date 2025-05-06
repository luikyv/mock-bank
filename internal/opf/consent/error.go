package consent

import "errors"

var (
	ErrNotFound                               = errors.New("consent not found")
	errAccessNotAllowed                       = errors.New("access to consent is not allowed")
	errInvalidPermissionGroup                 = errors.New("the requested permission groups are invalid")
	errInvalidExpiration                      = errors.New("the expiration date time is invalid")
	errPersonalAndBusinessPermissionsTogether = errors.New("cannot request personal and business permissions together")
	errAlreadyRejected                        = errors.New("the consent is already rejected")
	errExtensionNotAllowed                    = errors.New("the consent is not allowed to be extended")
	errCannotExtendConsentNotAuthorized       = errors.New("the consent is not in the AUTHORISED status")
	errCannotExtendConsentForJointAccount     = errors.New("a consent created for a joint account cannot be extended")
)
