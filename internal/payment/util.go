package payment

import (
	"time"

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
