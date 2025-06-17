package autopayment

import (
	"strings"

	"github.com/luiky/mock-bank/internal/consent"
)

func ConsentIDFromScopes(scopes string) (string, bool) {
	for _, s := range strings.Split(scopes, " ") {
		if ScopeConsentID.Matches(s) {
			return strings.TrimPrefix(s, "recurring-consent:"+consent.URNPrefix), true
		}
	}
	return "", false
}
