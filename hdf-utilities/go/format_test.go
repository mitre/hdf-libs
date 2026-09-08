package hdfutil

import (
	"fmt"
	"math"
	"testing"
)

// The rule is "whatever JavaScript's toFixed does", because the point is that a
// Go exporter and its TypeScript twin emit the same digits. Every expectation
// here was taken from node's toFixed, not from what fmt happens to produce.
func TestFormatFixed_MatchesToFixed(t *testing.T) {
	for _, tc := range []struct {
		value    float64
		prec     int
		want     string
		why      string
		fmtWould string // what %.*f gives, when it differs
	}{
		{7.25, 1, "7.3", "the tie this converter's card is named after", "7.2"},
		{0.25, 2, "0.25", "already exact at this precision", ""},
		{0.25, 1, "0.3", "the original impact tie", "0.2"},
		{0.125, 2, "0.13", "the tie precision alone moved it to", "0.12"},
		{0.625, 2, "0.63", "and its neighbour", "0.62"},
		{0.015625, 5, "0.01563", "an exact tie at five places, where EPSS renders", "0.01562"},
		{0.75, 1, "0.8", "a tie the two rules already agreed on", ""},
		{0.615, 2, "0.61", "scaling by 100 first would round this up, wrongly", ""},
		{1.005, 2, "1.00", "its binary value is below the tie", ""},
		{0.145, 2, "0.14", "ditto", ""},
		{0, 2, "0.00", "zero pads", ""},
		{1, 2, "1.00", "an integer pads", ""},
		{10, 1, "10.0", "a CVSS maximum", ""},
		{0.123455, 5, "0.12345", "not a tie: the double is 0.1234549999...", ""},
	} {
		t.Run(fmt.Sprintf("%v@%d", tc.value, tc.prec), func(t *testing.T) {
			if got := FormatFixed(tc.value, tc.prec); got != tc.want {
				t.Errorf("FormatFixed(%v, %d) = %q, want %q — %s", tc.value, tc.prec, got, tc.want, tc.why)
			}
			if tc.fmtWould != "" {
				if got := fmt.Sprintf("%.*f", tc.prec, tc.value); got != tc.fmtWould {
					t.Errorf("premise check: %%.%df of %v = %q, expected the helper to be replacing %q",
						tc.prec, tc.value, got, tc.fmtWould)
				}
			}
		})
	}
}

// toFixed strips the sign before choosing the digit, so it rounds halves away
// from zero on negatives too — the same rule, not a different one.
func TestFormatFixed_NegativesRoundAwayFromZero(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  string
	}{
		{-0.125, "-0.13"},
		{-0.25, "-0.25"},
		{-7.25, "-7.25"},
	} {
		if got := FormatFixed(tc.value, 2); got != tc.want {
			t.Errorf("FormatFixed(%v, 2) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// A value with no faithful fixed-point rendering yields "" rather than a
// misleading digit string.
func TestFormatFixed_NonFinite(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if got := FormatFixed(v, 2); got != "" {
			t.Errorf("FormatFixed(%v, 2) = %q, want \"\"", v, got)
		}
	}
}
