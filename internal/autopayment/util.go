package autopayment

import (
	"strconv"
	"strings"

	"github.com/luikyv/mock-bank/internal/consent"
)

func ConsentIDFromScopes(scopes string) (string, bool) {
	for _, s := range strings.Split(scopes, " ") {
		if ScopeConsentID.Matches(s) {
			return strings.TrimPrefix(s, "recurring-consent:"+consent.URNPrefix), true
		}
	}
	return "", false
}

func convertAmount(v string) float64 {
	f, _ := strconv.ParseFloat(v, 64)
	return f
}
