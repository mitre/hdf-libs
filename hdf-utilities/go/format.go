package hdfutil

import "math/big"

// FormatFixed renders a float with exactly prec decimal places, rounding halves
// away from zero — the rule JavaScript's Number.toFixed uses, so a Go exporter
// and its TypeScript twin emit the same digits. It is the display-side companion
// to RoundImpact, which rounds impact onto its canonical grid.
//
// fmt's %.*f cannot be used for this: it rounds halves to even, so a value whose
// exact binary expansion ends in a 5 at the cut point renders differently in the
// two languages (7.25 became "7.2" in Go and "7.3" in TypeScript). Rational
// arithmetic avoids the other trap too — scaling by a power of ten first
// introduces float error that flips values like 0.615 the wrong way.
//
// Matches toFixed for every finite value below 1e21. At or above that magnitude
// toFixed abandons fixed-point for exponential notation ("1e+21") while this
// keeps expanding the digits, so the two part company; no HDF field this formats
// (impact 0-1, CVSS 0-10, EPSS 0-1) comes near it.
func FormatFixed(v float64, prec int) string {
	r := new(big.Rat).SetFloat64(v)
	if r == nil {
		return "" // NaN or infinity: no faithful fixed-point rendering exists
	}
	return r.FloatString(prec)
}
