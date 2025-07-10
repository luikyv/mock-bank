package consent

import (
	"slices"
	"strings"

	"github.com/google/uuid"
)

func URN(id uuid.UUID) string {
	return URNPrefix + id.String()
}

func IDFromScopes(scopes string) (string, bool) {
	for s := range strings.SplitSeq(scopes, " ") {
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
