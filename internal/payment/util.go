package payment

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

// ParseEndToEndDate extracts and parses the datetime (yyyyMMddHHmm) from an end to end ID.
func ParseEndToEndDate(id string) (timeutil.DateTime, error) {
	dateStr := id[9:21]
	parsed, err := time.ParseInLocation(endToEndTimeFormat, dateStr, time.UTC)
	if err != nil {
		return timeutil.DateTime{}, err
	}

	return timeutil.NewDateTime(parsed), nil
}

func ConsentURN(id uuid.UUID) string {
	return ConsentURNPrefix + id.String()
}

func ConsentIDFromScopes(scopes string) (string, bool) {
	for s := range strings.SplitSeq(scopes, " ") {
		if consent.ScopeID.Matches(s) {
			return strings.TrimPrefix(s, "consent:"+ConsentURNPrefix), true
		}
	}
	return "", false
}

func SumPayments[T interface{ PaymentAmount() string }](payments []T) float64 {
	sum := 0.0
	for _, p := range payments {
		sum += ConvertAmount(p.PaymentAmount())
	}
	return sum
}

func ConvertAmount(v string) float64 {
	// TODO: Log this error.
	f, _ := strconv.ParseFloat(v, 64)
	return f
}
