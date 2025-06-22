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

// compareAmounts compares two string representations of float values.
func compareAmounts(low, high string) bool {
	lowF, _ := strconv.ParseFloat(low, 64)
	highF, _ := strconv.ParseFloat(high, 64)
	return lowF <= highF
}
