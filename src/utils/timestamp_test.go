package utils

import (
	"strings"
	"testing"
	"time"
)

// TestParseOptionalTimestampNilOrEmpty: nil/empty -> (nil, nil).
func TestParseOptionalTimestampNilOrEmpty(t *testing.T) {
	cases := []struct {
		name  string
		input *string
	}{
		{"nil_pointer", nil},
		{"empty_string", ptr("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseOptionalTimestamp(tc.input)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got != nil {
				t.Fatalf("expected nil Timestamp, got %v", got)
			}
		})
	}
}

// TestParseOptionalTimestampAcceptsEveryFormat: every accepted layout parses to the right UTC time.
func TestParseOptionalTimestampAcceptsEveryFormat(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Time
	}{
		{"rfc3339_with_z", "2026-01-02T15:04:05Z", time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"rfc3339_with_offset", "2026-01-02T15:04:05+02:00", time.Date(2026, 1, 2, 13, 4, 5, 0, time.UTC)},
		{"rfc3339_nano", "2026-01-02T15:04:05.123Z", time.Date(2026, 1, 2, 15, 4, 5, 123_000_000, time.UTC)},
		{"datetime_no_z_seconds", "2026-01-02T15:04:05", time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"datetime_no_z_minutes_only", "2026-01-02T15:04", time.Date(2026, 1, 2, 15, 4, 0, 0, time.UTC)},
		{"datetime_no_z_offset_seconds", "2026-01-02T15:04:05-05:00", time.Date(2026, 1, 2, 20, 4, 5, 0, time.UTC)},
		{"datetime_no_z_offset_minutes", "2026-01-02T15:04-05:00", time.Date(2026, 1, 2, 20, 4, 0, 0, time.UTC)},
		{"date_only", "2026-01-02", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseOptionalTimestamp(ptr(tc.raw))
			if err != nil {
				t.Fatalf("expected no error for %q, got %v", tc.raw, err)
			}
			if got == nil {
				t.Fatalf("expected a Timestamp, got nil for %q", tc.raw)
			}
			if !got.AsTime().Equal(tc.want) {
				t.Fatalf("parsed time for %q: want %v, got %v", tc.raw, tc.want, got.AsTime())
			}
		})
	}
}

// TestParseOptionalTimestampRejectsGarbage: invalid input -> nil + error echoing the value.
func TestParseOptionalTimestampRejectsGarbage(t *testing.T) {
	cases := []string{
		"yesterday",
		"2026/01/02",
		"2026-13-40",
		"15:04:05",
		"2026-01-02T",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			got, err := ParseOptionalTimestamp(ptr(raw))
			if err == nil {
				t.Fatalf("expected an error for %q, got nil (value=%v)", raw, got)
			}
			if got != nil {
				t.Fatalf("expected nil Timestamp on error, got %v", got)
			}
			if !strings.Contains(err.Error(), raw) {
				t.Errorf("error should echo the offending value %q, got %q", raw, err.Error())
			}
		})
	}
}

// TestDerefStringNilAndValue: nil-safe accessor.
func TestDerefStringNilAndValue(t *testing.T) {
	if DerefString(nil) != "" {
		t.Errorf("nil pointer should yield empty string")
	}
	if DerefString(ptr("hello")) != "hello" {
		t.Errorf("expected %q, got %q", "hello", DerefString(ptr("hello")))
	}
}

// TestTimestampFieldErrorDetail: detail mentions the value and accepted formats.
func TestTimestampFieldErrorDetail(t *testing.T) {
	e := &TimestampFieldError{Field: "date_from", Value: "not-a-date"}
	detail := e.Detail()
	if !strings.Contains(detail, "not-a-date") {
		t.Errorf("detail should echo offending value, got %q", detail)
	}
	if !strings.Contains(detail, AcceptedTimestampFormatSentinel()) {
		t.Errorf("detail should mention the accepted-formats hint, got %q", detail)
	}
}

// TestTimestampFieldErrorString: Error() starts with the field name.
func TestTimestampFieldErrorString(t *testing.T) {
	e := &TimestampFieldError{Field: "date_from", Value: "x"}
	if !strings.HasPrefix(e.Error(), "invalid date_from") {
		t.Errorf("expected Error() to start with field name, got %q", e.Error())
	}
}

func ptr(s string) *string { return &s }

// AcceptedTimestampFormatSentinel pins a substring inside AcceptedTimestampFormats so the
// detail assertion stays stable if the long description is rewritten.
func AcceptedTimestampFormatSentinel() string {
	return "RFC3339"
}
