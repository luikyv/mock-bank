package autopayment

import (
	"strings"

	"github.com/google/uuid"
)

func ConsentURN(id uuid.UUID) string {
	return ConsentURNPrefix + id.String()
}

func ConsentIDFromScopes(scopes string) (string, bool) {
	for s := range strings.SplitSeq(scopes, " ") {
		if ScopeConsentID.Matches(s) {
			return strings.TrimPrefix(s, "recurring-consent:"+ConsentURNPrefix), true
		}
	}
	return "", false
}
