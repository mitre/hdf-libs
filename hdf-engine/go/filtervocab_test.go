package hdfengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanonicalStatusFilter(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"schema spelling", "notApplicable", "notApplicable", true},
		{"cli snake_case spelling", "not_applicable", "notApplicable", true},
		{"cli snake_case not_reviewed", "not_reviewed", "notReviewed", true},
		{"upper case", "FAILED", "failed", true},
		{"mixed case snake", "Not_Reviewed", "notReviewed", true},
		{"surrounding whitespace", "  passed  ", "passed", true},
		{"error", "error", "error", true},
		{"typo", "bogus_value", "", false},
		{"near miss", "fail", "", false},
		{"empty", "", "", false},
		{"severity value is not a status", "critical", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CanonicalStatusFilter(tt.in)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCanonicalSeverityFilter(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"schema spelling", "critical", "critical", true},
		{"informational", "informational", "informational", true},
		{"pre-3.7 none spelling", "none", "informational", true},
		{"upper case", "HIGH", "high", true},
		{"surrounding whitespace", " medium ", "medium", true},
		{"low", "low", "low", true},
		{"typo", "crit", "", false},
		{"empty", "", "", false},
		{"status value is not a severity", "failed", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CanonicalSeverityFilter(tt.in)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// The value lists are what a caller prints in a refusal, so they are the schema
// vocabularies in schema order — not the accepted alias spellings.
func TestFilterValueLists(t *testing.T) {
	assert.Equal(t, []string{"passed", "failed", "notApplicable", "notReviewed", "error"}, StatusFilterValues())
	assert.Equal(t, []string{"critical", "high", "medium", "low", "informational"}, SeverityFilterValues())
}

// Every advertised value must canonicalize to itself, so a caller that copies a
// value out of a refusal message gets an accepted filter back.
func TestFilterValueListsRoundTrip(t *testing.T) {
	for _, s := range StatusFilterValues() {
		got, ok := CanonicalStatusFilter(s)
		assert.True(t, ok, "advertised status %q must be accepted", s)
		assert.Equal(t, s, got)
	}
	for _, s := range SeverityFilterValues() {
		got, ok := CanonicalSeverityFilter(s)
		assert.True(t, ok, "advertised severity %q must be accepted", s)
		assert.Equal(t, s, got)
	}
}

// A mutated StatusFilterValues must not silently widen what Filter accepts: the
// canonical form is the schema Result_Status spelling the engine compares
// against, so no translation happens between canonicalization and matching.
func TestCanonicalStatusMatchesSchemaSpelling(t *testing.T) {
	got, ok := CanonicalStatusFilter("not_applicable")
	assert.True(t, ok)
	assert.Equal(t, "notApplicable", got)
}
