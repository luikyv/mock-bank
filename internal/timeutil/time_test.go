package timeutil

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDateTime_MarshalJSON(t *testing.T) {
	// Given.
	tests := []struct {
		name     string
		datetime DateTime
		want     string
	}{
		{
			name:     "should marshal datetime to JSON",
			datetime: NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)),
			want:     `"2023-12-25T15:30:45Z"`,
		},
		{
			name:     "should marshal zero time",
			datetime: DateTime{},
			want:     `"0001-01-01T00:00:00Z"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			got, err := json.Marshal(tt.datetime)

			// Then.
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestDateTime_UnmarshalJSON(t *testing.T) {
	// Given.
	tests := []struct {
		name    string
		data    string
		want    DateTime
		wantErr bool
	}{
		{
			name:    "should unmarshal valid datetime",
			data:    `"2023-12-25T15:30:45Z"`,
			want:    NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)),
			wantErr: false,
		},
		{
			name:    "should return error for invalid JSON",
			data:    `invalid json`,
			wantErr: true,
		},
		{
			name:    "should return error for invalid datetime format",
			data:    `"2023-12-25"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			var got DateTime
			err := json.Unmarshal([]byte(tt.data), &got)

			// Then.
			if tt.wantErr {
				if err == nil {
					t.Error("got nil, expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want.Time) {
				t.Errorf("got %v, want %v", got.Time, tt.want.Time)
			}
		})
	}
}

func TestDateTime_Scan(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		want    DateTime
		wantErr bool
	}{
		{
			name:    "should scan time.Time value",
			value:   time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC),
			want:    NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)),
			wantErr: false,
		},
		{
			name:    "should handle nil value",
			value:   nil,
			want:    DateTime{},
			wantErr: false,
		},
		{
			name:    "should return error for non-time value",
			value:   "not a time",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DateTime
			err := got.Scan(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want.Time) {
				t.Errorf("got %v, want %v", got.Time, tt.want.Time)
			}
		})
	}
}

func TestDateTime_Value(t *testing.T) {
	dt := NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC))
	value, err := dt.Value()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	timeValue, ok := value.(time.Time)
	if !ok {
		t.Fatalf("expected time.Time, got %T", value)
	}

	if !timeValue.Equal(dt.Time) {
		t.Errorf("got %v, want %v", timeValue, dt.Time)
	}
}

func TestDateTime_String(t *testing.T) {
	// Given.
	dt := NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC))

	// When.
	got := dt.String()

	// Then.
	want := "2023-12-25T15:30:45Z"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestDateTime_Add(t *testing.T) {
	// Given.
	dt := NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC))

	// When.
	added := dt.Add(24 * time.Hour)

	// Then.
	expected := NewDateTime(time.Date(2023, 12, 26, 15, 30, 45, 0, time.UTC))
	if !added.Equal(expected.Time) {
		t.Errorf("got %v, want %v", added.Time, expected.Time)
	}
}

func TestDateTime_Before(t *testing.T) {
	// Given.
	dt1 := NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC))
	dt2 := NewDateTime(time.Date(2023, 12, 26, 15, 30, 45, 0, time.UTC))

	// Then.
	if !dt1.Before(dt2) {
		t.Error("expected dt1 to be before dt2")
	}

	if dt2.Before(dt1) {
		t.Error("expected dt2 to not be before dt1")
	}
}

func TestDateTimeNow(t *testing.T) {
	// Given
	before := DateTimeNow()
	dt := DateTimeNow()
	after := DateTimeNow()

	// Then.
	if dt.Before(before) || dt.After(after) {
		t.Errorf("DateTimeNow() returned time outside expected range: %v", dt.Time)
	}
}

func TestNewDateTime(t *testing.T) {
	// Given.
	input := time.Date(2023, 12, 25, 15, 30, 45, 0, time.Local)

	// When.
	dt := NewDateTime(input)

	// Then.
	if dt.Location() != time.UTC {
		t.Errorf("expected UTC location, got %v", dt.Location())
	}

	if !dt.Equal(input) {
		t.Errorf("got %v, want %v", dt.Time, input)
	}
}

func TestBrazilDate_MarshalJSON(t *testing.T) {
	// Given.
	tests := []struct {
		name string
		date BrazilDate
		want string
	}{
		{
			name: "should marshal date to JSON",
			date: NewBrazilDate(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)),
			want: `"2023-12-25"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			got, err := json.Marshal(tt.date)

			// Then.
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestBrazilDate_UnmarshalJSON(t *testing.T) {
	// Given.
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "should unmarshal valid date",
			data:    `"2023-12-25"`,
			wantErr: false,
		},
		{
			name:    "should return error for invalid JSON",
			data:    `invalid json`,
			wantErr: true,
		},
		{
			name:    "should return error for invalid date format",
			data:    `"2023-12-25T15:30:45Z"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			var got BrazilDate
			err := json.Unmarshal([]byte(tt.data), &got)

			// Then.
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBrazilDate_Scan(t *testing.T) {
	// Given.
	tests := []struct {
		name    string
		value   any
		wantErr bool
	}{
		{
			name:    "should scan time.Time value",
			value:   time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC),
			wantErr: false,
		},
		{
			name:    "should handle nil value",
			value:   nil,
			wantErr: false,
		},
		{
			name:    "should return error for non-time value",
			value:   "not a time",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			var got BrazilDate
			err := got.Scan(tt.value)

			// Then.
			if tt.wantErr {
				if err == nil {
					t.Error("got nil, expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBrazilDate_Value(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC))

	// When.
	value, err := date.Value()

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	timeValue, ok := value.(time.Time)
	if !ok {
		t.Fatalf("got %T, want time.Time", value)
	}

	if timeValue.Location().String() != "America/Sao_Paulo" {
		t.Errorf("got %v, want America/Sao_Paulo", timeValue.Location())
	}

	if timeValue.Hour() != 0 || timeValue.Minute() != 0 || timeValue.Second() != 0 {
		t.Errorf("got %v, want midnight", timeValue)
	}
}

func TestBrazilDate_String(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 1, 30, 45, 0, time.UTC))

	// When.
	got := date.String()

	// Then.
	want := "2023-12-24"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestBrazilDate_AddDate(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 0, 0, 0, 0, time.UTC))

	// When.
	added := date.AddDate(0, 1, 0) // Add 1 month.

	// Then.
	expected := NewBrazilDate(time.Date(2024, 1, 25, 0, 0, 0, 0, time.UTC))
	if !added.Time.Equal(expected.Time) {
		t.Errorf("got %v, want %v", added.Time, expected.Time)
	}
}

func TestBrazilDate_Equal(t *testing.T) {
	// Given.
	date1 := NewBrazilDate(time.Date(2023, 12, 25, 0, 0, 0, 0, time.UTC))
	date2 := NewBrazilDate(time.Date(2023, 12, 25, 0, 0, 0, 0, time.UTC))
	date3 := NewBrazilDate(time.Date(2023, 12, 26, 0, 0, 0, 0, time.UTC))

	// Then.
	if !date1.Equal(date2) {
		t.Error("got false, want true")
	}

	if date1.Equal(date3) {
		t.Error("expected date1 to not equal date3")
	}
}

func TestBrazilDate_After(t *testing.T) {
	// Given.
	date1 := NewBrazilDate(time.Date(2023, 12, 25, 0, 0, 0, 0, time.UTC))
	date2 := NewBrazilDate(time.Date(2023, 12, 26, 0, 0, 0, 0, time.UTC))

	// Then.
	if date1.After(date2) {
		t.Error("expected date1 to not be after date2")
	}

	if !date2.After(date1) {
		t.Error("expected date2 to be after date1")
	}
}

func TestBrazilDate_Before(t *testing.T) {
	// Given.
	date1 := NewBrazilDate(time.Date(2023, 12, 25, 0, 0, 0, 0, time.UTC))
	date2 := NewBrazilDate(time.Date(2023, 12, 26, 0, 0, 0, 0, time.UTC))

	// Then.
	if !date1.Before(date2) {
		t.Error("expected date1 to be before date2")
	}

	if date2.Before(date1) {
		t.Error("expected date2 to not be before date1")
	}
}

func TestBrazilDate_StartOfWeek(t *testing.T) {
	// Given.
	tests := []struct {
		name     string
		date     BrazilDate
		expected BrazilDate
	}{
		{
			name:     "Monday should return same day",
			date:     NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC)), // Monday.
			expected: NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC)),
		},
		{
			name:     "Wednesday should return Monday",
			date:     NewBrazilDate(time.Date(2023, 12, 27, 15, 0, 0, 0, time.UTC)), // Wednesday
			expected: NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC)),
		},
		{
			name:     "Sunday should return Monday",
			date:     NewBrazilDate(time.Date(2023, 12, 31, 15, 0, 0, 0, time.UTC)), // Sunday.
			expected: NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			got := tt.date.StartOfWeek()

			// Then.
			if !got.Time.Equal(tt.expected.Time) {
				t.Errorf("got %v, want %v", got.Time, tt.expected.Time)
			}
		})
	}
}

func TestBrazilDate_EndOfWeek(t *testing.T) {
	// Given.
	tests := []struct {
		name     string
		date     BrazilDate
		expected BrazilDate
	}{
		{
			name:     "Monday should return Sunday",
			date:     NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC)), // Monday.
			expected: NewBrazilDate(time.Date(2023, 12, 31, 15, 0, 0, 0, time.UTC)),
		},
		{
			name:     "Sunday should return same day",
			date:     NewBrazilDate(time.Date(2023, 12, 31, 15, 0, 0, 0, time.UTC)), // Sunday.
			expected: NewBrazilDate(time.Date(2023, 12, 31, 15, 0, 0, 0, time.UTC)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			got := tt.date.EndOfWeek()

			// Then.
			if !got.Time.Equal(tt.expected.Time) {
				t.Errorf("got %v, want %v", got.Time, tt.expected.Time)
			}
		})
	}
}

func TestBrazilDate_StartOfMonth(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC))

	// When.
	got := date.StartOfMonth()

	// Then.
	expected := NewBrazilDate(time.Date(2023, 12, 1, 15, 0, 0, 0, time.UTC))
	if !got.Time.Equal(expected.Time) {
		t.Errorf("got %v, want %v", got.Time, expected.Time)
	}
}

func TestBrazilDate_EndOfMonth(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC))

	// When.
	got := date.EndOfMonth()

	// Then.
	expected := NewBrazilDate(time.Date(2023, 12, 31, 15, 0, 0, 0, time.UTC))
	if !got.Time.Equal(expected.Time) {
		t.Errorf("got %v, want %v", got.Time, expected.Time)
	}
}

func TestBrazilDate_StartOfYear(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC))

	// When.
	got := date.StartOfYear()

	// Then.
	expected := NewBrazilDate(time.Date(2023, 1, 1, 15, 0, 0, 0, time.UTC))
	if !got.Time.Equal(expected.Time) {
		t.Errorf("got %v, want %v", got.Time, expected.Time)
	}
}

func TestBrazilDate_EndOfYear(t *testing.T) {
	// Given.
	date := NewBrazilDate(time.Date(2023, 12, 25, 15, 0, 0, 0, time.UTC))

	// When.
	got := date.EndOfYear()

	// Then.
	expected := NewBrazilDate(time.Date(2023, 12, 31, 15, 0, 0, 0, time.UTC))
	if !got.Time.Equal(expected.Time) {
		t.Errorf("got %v, want %v", got.Time, expected.Time)
	}
}

func TestBrazilDateNow(t *testing.T) {
	// Given.
	before := time.Now().UTC()
	date := BrazilDateNow()
	after := time.Now().UTC()

	// Then.
	if date.Time.Location().String() != "America/Sao_Paulo" {
		t.Errorf("expected America/Sao_Paulo location, got %v", date.Location())
	}

	if date.Hour() != 0 || date.Minute() != 0 || date.Second() != 0 {
		t.Errorf("expected midnight time, got %v", date.Time)
	}

	beforeDate := NewBrazilDate(before)
	afterDate := NewBrazilDate(after)
	if date.Time.Before(beforeDate.Time) || date.Time.After(afterDate.Time) {
		t.Errorf("BrazilDateNow() returned date outside expected range: %v", date.Time)
	}
}

func TestNewBrazilDate(t *testing.T) {
	// Given.
	input := time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)

	// When.
	date := NewBrazilDate(input)

	// Then.
	if date.Time.Location().String() != "America/Sao_Paulo" {
		t.Errorf("expected America/Sao_Paulo location, got %v", date.Location())
	}

	if date.Hour() != 0 || date.Minute() != 0 || date.Second() != 0 {
		t.Errorf("expected midnight time, got %v", date.Time)
	}

	if date.Year() != 2023 || date.Month() != 12 || date.Day() != 25 {
		t.Errorf("expected date 2023-12-25, got %v", date.Time)
	}
}

func TestTimestamp(t *testing.T) {
	// Given.
	before := time.Now().UTC().Unix()

	// When.
	ts := Timestamp()

	// Then.
	after := time.Now().UTC().Unix()

	if int64(ts) < before || int64(ts) > after {
		t.Errorf("Timestamp() returned value outside expected range: %d", ts)
	}
}

func TestParseTimestamp(t *testing.T) {
	// Given.
	expectedTime := time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)
	timestamp := int(expectedTime.Unix())

	// When.
	dt := ParseTimestamp(timestamp)

	// Then.
	if !dt.Equal(expectedTime) {
		t.Errorf("got %v, want %v", dt.Time, expectedTime)
	}
}

func TestDateTime_BrazilDate(t *testing.T) {
	// Given.
	dt := NewDateTime(time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC))

	// When.
	brDate := dt.BrazilDate()

	// Then.
	if brDate.Time.Location().String() != "America/Sao_Paulo" {
		t.Errorf("expected America/Sao_Paulo location, got %v", brDate.Location())
	}

	if brDate.Hour() != 0 || brDate.Minute() != 0 || brDate.Second() != 0 {
		t.Errorf("expected midnight time, got %v", brDate.Time)
	}

	if brDate.Year() != 2023 || brDate.Month() != 12 || brDate.Day() != 25 {
		t.Errorf("expected date 2023-12-25, got %v", brDate.Time)
	}
}
