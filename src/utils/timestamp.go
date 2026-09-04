package utils

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// AcceptedTimestampFormats lists every form ParseOptionalTimestamp accepts.
const AcceptedTimestampFormats = "RFC3339 (e.g. 2026-01-02T15:04:05Z, 2026-01-02T15:04:05+02:00, or 2026-01-02T15:04:05.123Z), datetime without seconds (2026-01-02T15:04Z), datetime without timezone (2026-01-02T15:04:05 or 2026-01-02T15:04), or date-only (2026-01-02)"

// optionalTimestampLayouts is tried in order; first match wins.
var optionalTimestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// ParseOptionalTimestamp parses an optional timestamp; nil/empty -> (nil, nil).
func ParseOptionalTimestamp(value *string) (*timestamppb.Timestamp, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	for _, layout := range optionalTimestampLayouts {
		if parsed, err := time.Parse(layout, *value); err == nil {
			return timestamppb.New(parsed), nil
		}
	}
	return nil, fmt.Errorf("invalid timestamp %q", *value)
}

// DerefString returns "" when s is nil.
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TimestampFieldError is one per-field parse failure.
type TimestampFieldError struct {
	Field string
	Value string
}

// Error is the short, log-friendly form ("invalid date_from: invalid timestamp \"x\"").
func (e *TimestampFieldError) Error() string {
	return fmt.Sprintf("invalid %s: invalid timestamp %q", e.Field, e.Value)
}

// Detail is the long form for the 400 `details` map (includes accepted formats).
func (e *TimestampFieldError) Detail() string {
	return fmt.Sprintf("invalid timestamp %q (expected %s)", e.Value, AcceptedTimestampFormats)
}
