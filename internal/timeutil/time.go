package timeutil

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

const (
	DateTimeMillisFormat = "2006-01-02T15:04:05.000Z"
	dateTimeFormat       = "2006-01-02T15:04:05Z"
	dateFormat           = "2006-01-02"
)

var brazilLocation *time.Location

func init() {
	brLocation, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		panic(err)
	}
	brazilLocation = brLocation
}

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

func (d *DateTime) Scan(value any) error {
	if value == nil {
		return nil
	}

	t, ok := value.(time.Time)
	if !ok {
		return errors.New("failed to scan DateTime: value is not time.Time")
	}

	d.Time = t.UTC()
	return nil
}

func (d DateTime) Value() (driver.Value, error) {
	return d.UTC(), nil
}

func (d DateTime) String() string {
	return d.Format(dateTimeFormat)
}

func (d DateTime) BrazilDate() BrazilDate {
	return NewBrazilDate(d.Time)
}

func (d DateTime) Add(duration time.Duration) DateTime {
	return DateTime{
		Time: d.Time.Add(duration),
	}
}

func (d DateTime) Before(t DateTime) bool {
	return d.Time.Before(t.Time)
}

func (d DateTime) After(t DateTime) bool {
	return d.Time.After(t.Time)
}

func (d DateTime) AddDate(years int, months int, days int) DateTime {
	return NewDateTime(d.Time.AddDate(years, months, days))
}

func (d DateTime) StartOfDay() DateTime {
	return NewDateTime(time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location()))
}

func (d DateTime) EndOfDay() DateTime {
	return NewDateTime(time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 999999999, d.Location()))
}

func DateTimeNow() DateTime {
	return NewDateTime(now())
}

func NewDateTime(t time.Time) DateTime {
	return DateTime{
		Time: t.In(time.UTC),
	}
}

type BrazilDate struct {
	time.Time
}

func (d BrazilDate) DateTime() DateTime {
	return NewDateTime(d.Time)
}

func (d BrazilDate) AddDate(years int, months int, days int) BrazilDate {
	return NewBrazilDate(d.Time.AddDate(years, months, days))
}

func (d BrazilDate) Equal(t BrazilDate) bool {
	return d.Time.Equal(t.Time)
}

func (d BrazilDate) After(t BrazilDate) bool {
	return d.Time.After(t.Time)
}

func (d BrazilDate) Before(t BrazilDate) bool {
	return d.Time.Before(t.Time)
}

func (d BrazilDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *BrazilDate) UnmarshalJSON(data []byte) error {
	var dateStr string
	if err := json.Unmarshal(data, &dateStr); err != nil {
		return err
	}

	parsed, err := ParseBrazilDate(dateStr)
	if err != nil {
		return err
	}

	d.Time = parsed.Time
	return nil
}

func (d BrazilDate) String() string {
	return d.Format(dateFormat)
}

func (d *BrazilDate) Scan(value any) error {
	if value == nil {
		return nil
	}

	t, ok := value.(time.Time)
	if !ok {
		return errors.New("failed to scan Date: value is not time.Time")
	}

	d.Time = time.Date(t.Year(), t.Month(), t.Day(), 12, 0, 0, 0, brazilLocation)
	return nil
}

func (d BrazilDate) Value() (driver.Value, error) {
	t := time.Date(d.Year(), d.Month(), d.Day(), 12, 0, 0, 0, brazilLocation)
	return t, nil
}

func (d BrazilDate) StartOfDay() BrazilDate {
	return BrazilDate{
		Time: time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, brazilLocation),
	}
}

func (d BrazilDate) EndOfDay() BrazilDate {
	return BrazilDate{
		Time: time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 999999999, brazilLocation),
	}
}

// StartOfWeek returns a new BrazilDate representing the start of the current week (Monday).
func (d BrazilDate) StartOfWeek() BrazilDate {
	weekDay := int(d.Weekday())
	if weekDay == 0 {
		weekDay = 7
	}
	daysSinceMonday := weekDay - 1
	return d.AddDate(0, 0, -daysSinceMonday)
}

// EndOfWeek returns a new BrazilDate representing the end of the current week (Sunday).
func (d BrazilDate) EndOfWeek() BrazilDate {
	weekDay := int(d.Weekday())
	if weekDay == 0 {
		weekDay = 7
	}
	return d.AddDate(0, 0, 7-weekDay)
}

func (d BrazilDate) StartOfMonth() BrazilDate {
	return NewBrazilDate(time.Date(d.Year(), d.Month(), 1, 12, 0, 0, 0, d.Location()))
}

func (d BrazilDate) EndOfMonth() BrazilDate {
	firstOfNextMonth := time.Date(d.Year(), d.Month()+1, 1, 12, 0, 0, 0, d.Location())
	return NewBrazilDate(firstOfNextMonth.AddDate(0, 0, -1))
}

func (d BrazilDate) StartOfYear() BrazilDate {
	return NewBrazilDate(time.Date(d.Year(), 1, 1, 12, 0, 0, 0, d.Location()))
}

func (d BrazilDate) EndOfYear() BrazilDate {
	return NewBrazilDate(time.Date(d.Year(), 12, 31, 12, 0, 0, 0, d.Location()))
}

func (d BrazilDate) WithDay(day int) BrazilDate {
	return NewBrazilDate(time.Date(d.Year(), d.Month(), day, 12, 0, 0, 0, d.Location()))
}

func (d BrazilDate) IsZero() bool {
	return d.Time.IsZero()
}

func BrazilDateNow() BrazilDate {
	return NewBrazilDate(now())
}

func NewBrazilDate(t time.Time) BrazilDate {
	brTime := t.In(brazilLocation)
	return BrazilDate{
		Time: time.Date(brTime.Year(), brTime.Month(), brTime.Day(), 12, 0, 0, 0, brazilLocation),
	}
}

func ParseBrazilDate(s string) (BrazilDate, error) {
	t, err := time.ParseInLocation(dateFormat, s, brazilLocation)
	if err != nil {
		return BrazilDate{}, err
	}
	return NewBrazilDate(t), nil
}

// Now returns the current time in UTC.
func now() time.Time {
	return time.Now().UTC()
}

// Timestamp returns the current Unix timestamp in seconds (UTC).
func Timestamp() int {
	return int(now().Unix())
}

func ParseTimestamp(ts int) DateTime {
	return NewDateTime(time.Unix(int64(ts), 0))
}
