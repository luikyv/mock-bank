package timex

import (
	"encoding/json"
	"time"
)

const (
	dateTimeFormat = "2006-01-02T15:04:05Z"
	dateFormat     = "2006-01-02"
)

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
	// TODO: Date should be in Brazil timezone.
	time.Time
}

func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Date) UnmarshalJSON(data []byte) error {
	var dateStr string
	err := json.Unmarshal(data, &dateStr)
	if err != nil {
		return err
	}

	parsed, err := time.Parse(dateFormat, dateStr)
	if err != nil {
		return err
	}

	d.Time = parsed.UTC()
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
