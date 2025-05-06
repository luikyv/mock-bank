package timex

import (
	"encoding/json"
	"time"
)

const (
	dateTimeFormat = "2006-01-02T15:04:05Z"
	dateFormat     = "2006-01-02"
)

var (
	brazilLocation, _ = time.LoadLocation("America/Sao_Paulo")
)

// TODO: Add db functions.
type DateTime struct {
	time.Time
}

func (d DateTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *DateTime) UnmarshalJSON(data []byte) error {
	var dateStr string
	err := json.Unmarshal(data, &dateStr)
	if err != nil {
		return err
	}

	parsed, err := time.Parse(dateTimeFormat, dateStr)
	if err != nil {
		return err
	}

	d.Time = parsed.UTC()
	return nil
}

func (d DateTime) String() string {
	return d.Time.Format(dateTimeFormat)
}

func (d DateTime) ToDate() Date {
	return NewDate(d.Time.Truncate(24 * time.Hour))
}

func NewDateTime(t time.Time) DateTime {
	return DateTime{
		Time: t,
	}
}

func DateTimeNow() DateTime {
	return NewDateTime(Now())
}

type Date struct {
	time.Time
}

func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return json.Marshal(nil)
	}

	t := d.In(brazilLocation)
	return json.Marshal(t.Format(dateFormat))
}

func (d *Date) UnmarshalJSON(data []byte) error {
	var dateStr string
	if err := json.Unmarshal(data, &dateStr); err != nil {
		return err
	}

	if dateStr == "" {
		d.Time = time.Time{}
		return nil
	}

	parsed, err := time.ParseInLocation(dateFormat, dateStr, brazilLocation)
	if err != nil {
		return err
	}

	d.Time = parsed
	return nil
}

func (d Date) String() string {
	return d.Time.Format(dateFormat)
}

func NewDate(t time.Time) Date {
	return Date{
		Time: t.Truncate(24 * time.Hour),
	}
}

func DateNow() Date {
	return NewDate(Now())
}

func ParseDate(s string) (Date, error) {
	parsed, err := time.Parse(dateFormat, s)
	if err != nil {
		return Date{}, err
	}

	return Date{
		Time: parsed.UTC(),
	}, nil
}

func Now() time.Time {
	return time.Now().UTC()
}

func Timestamp() int {
	return int(Now().Unix())
}
