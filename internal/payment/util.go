package payment

import (
	"strconv"
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
	return consent.IDFromScopes(scopes)
}

func ConvertAmount(v string) float64 {
	f, _ := strconv.ParseFloat(v, 64)
	return f
}
