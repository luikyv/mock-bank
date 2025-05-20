package consent

import (
	"slices"
	"strings"

	"github.com/luiky/mock-bank/internal/timeutil"
)

func IDFromScopes(scopes string) (string, bool) {
	for _, s := range strings.Split(scopes, " ") {
		if ScopeID.Matches(s) {
			return strings.TrimPrefix(s, "consent:"+URNPrefix), true
		}
	}
	return "", false
}

func validatePermissions(requestedPermissions []Permission) error {

permissionsLoop:
	// Make sure if a permission is requested, at least one group of permissions
	// containing it is requested as well.
	for _, requestedPermission := range requestedPermissions {
		for _, group := range PermissionGroups {

			if slices.Contains(group, requestedPermission) && containsAll(requestedPermissions, group...) {
				continue permissionsLoop
			}

		}

		// Return an error if there is no group that contains requestedPermission
		// and is fully present in requestedPermissions.
		return ErrInvalidPermissionGroup
	}

	return validatePersonalAndBusinessPermissions(requestedPermissions)
}

func validatePersonalAndBusinessPermissions(requestedPermissions []Permission) error {
	isPersonal := containsAny(requestedPermissions,
		PermissionCustomersPersonalIdentificationsRead,
		PermissionCustomersPersonalAdittionalInfoRead,
	)
	isBusiness := containsAny(requestedPermissions,
		PermissionCustomersBusinessIdentificationsRead,
		PermissionCustomersBusinessAdittionalInfoRead,
	)

	if isPersonal && isBusiness {
		return ErrPersonalAndBusinessPermissionsTogether
	}

	return nil
}

func validateExtension(c *Consent, ext *Extension) error {
	if !c.IsAuthorized() {
		return ErrCannotExtendConsentNotAuthorized
	}

	if c.UserCPF != ext.UserCPF {
		return ErrExtensionNotAllowed
	}

	if c.BusinessCNPJ != "" && c.BusinessCNPJ != ext.BusinessCNPJ {
		return ErrExtensionNotAllowed
	}

	if ext.ExpiresAt == nil {
		return nil
	}

	now := timeutil.Now()
	if ext.ExpiresAt.Before(now) || ext.ExpiresAt.After(now.AddDate(1, 0, 0)) {
		return ErrInvalidExpiration
	}

	if c.ExpiresAt != nil && !ext.ExpiresAt.After(*c.ExpiresAt) {
		return ErrInvalidExpiration
	}

	return nil
}

func containsAll[T comparable](superSet []T, subSet ...T) bool {
	for _, t := range subSet {
		if !slices.Contains(superSet, t) {
			return false
		}
	}

	return true
}

func containsAny[T comparable](slice1 []T, slice2 ...T) bool {
	for _, t := range slice2 {
		if slices.Contains(slice1, t) {
			return true
		}
	}

	return false
}
