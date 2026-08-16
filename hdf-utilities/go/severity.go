// Package hdfutil provides shared utility functions for HDF converters and tools.
package hdfutil

import (
	"math"
	"strings"
)

// standardSeverityMap defines the canonical severity-to-impact mappings used
// across most HDF converters, aligned with CVSS 3.x bands normalized to 0-1.
// Each value is the floor of its band. The inverse (ImpactToSeverity) uses
// these thresholds: >=0.9 critical, [0.7,0.9) high, [0.4,0.7) medium,
// (0,0.4) low, 0.0 informational. Case-insensitive lookup handled by caller.
var standardSeverityMap = map[string]float64{
	"critical":      0.9,
	"high":          0.7,
	"medium":        0.5,
	"low":           0.3,
	"info":          0.0,
	"none":          0.0,
	"informational": 0.0,
	"information":   0.0,
}

// SeverityToImpact maps a standard severity string to an HDF impact value.
// Case-insensitive. Returns defaultVal if severity is not recognized.
// Standard mappings: critical=0.9, high=0.7, medium=0.5, low=0.3,
// info/none/informational/information=0.0.
//
// For documents with no severity assessment (NIST 800-53 catalogs, FedRAMP
// baselines, etc.), callers should branch on absence at the call site rather
// than calling this function — Go has no null-input pathway analogous to the
// TypeScript counterpart's `severityToImpact(null) → null` overload.
func SeverityToImpact(severity string, defaultVal float64) float64 {
	if impact, ok := standardSeverityMap[strings.ToLower(severity)]; ok {
		return impact
	}
	return defaultVal
}

// RoundImpact rounds an HDF impact value to 2 decimal places — its canonical
// precision — eliminating the representation noise that binary float division
// leaves in serialized output (e.g. score/10 → 0.9800000000000001). Impact is
// defined on 0.0–1.0 with a natural 0.01 grid (a 1-decimal CVSS score / 10), so
// this is lossless in intent. Use it wherever impact is COMPUTED (divided or
// otherwise arithmetically derived), not when assigned from a literal band.
func RoundImpact(x float64) float64 {
	return math.Round(x*100) / 100
}

// SeverityToImpactWithAliases maps severity to impact, checking custom aliases
// first, then falling back to standard mappings. Use for tools with non-standard
// severity labels (e.g., sonarqube BLOCKER, veracode numeric levels, grype
// critical=0.9). Aliases are matched case-insensitively.
func SeverityToImpactWithAliases(severity string, aliases map[string]float64, defaultVal float64) float64 {
	lower := strings.ToLower(severity)
	if impact, ok := aliases[lower]; ok {
		return impact
	}
	if impact, ok := standardSeverityMap[lower]; ok {
		return impact
	}
	return defaultVal
}

// CvssScoreToSeverity maps a raw CVSS base score (0.0–10.0) to a FIRST
// qualitative severity band:
//
//	none     = 0.0
//	low      = 0.1 – 3.9
//	medium   = 4.0 – 6.9
//	high     = 7.0 – 8.9
//	critical = 9.0 – 10.0
//
// Out-of-range scores are clamped: anything below the low-band floor (0.1)
// becomes "none"; anything above 10.0 becomes "critical". This mirrors
// scanner behavior and avoids throwing on malformed inputs.
func CvssScoreToSeverity(score float64) string {
	switch {
	case math.IsNaN(score) || math.IsInf(score, 0):
		// Match the TypeScript counterpart, which returns "none" for any
		// non-finite input (NaN comparisons are false in Go and would
		// otherwise fall through to "critical").
		return "none"
	case score < 0.1:
		return "none"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

// ImpactToSeverity maps an HDF impact score (0.0–1.0) to a severity string.
// This is the inverse of SeverityToImpact. Threshold ranges:
//
//	>=0.9 = critical, [0.7,0.9) = high, [0.4,0.7) = medium,
//	(0,0.4) = low, 0.0 = informational
//
// For documents with no impact assessment, callers should branch on absence at
// the call site rather than passing a placeholder — Go has no null-input
// pathway analogous to the TypeScript counterpart's
// `impactToSeverity(null) → null` overload.
func ImpactToSeverity(impact float64) string {
	switch {
	case impact >= 0.9:
		return "critical"
	case impact >= 0.7:
		return "high"
	case impact >= 0.4:
		return "medium"
	case impact > 0:
		return "low"
	default:
		return "informational"
	}
}

// unratedSeverityTokens are the severity vocabulary values that assert "no
// rating was made" (grype Unknown, Dependency-Track UNASSIGNED, Microsoft
// Graph unSpecified). Distinct from the zero-impact RATED tier
// (info/none/informational) and from grype's negligible, which is the lowest
// rating, not an absent one.
var unratedSeverityTokens = map[string]bool{
	"unknown":     true,
	"unassigned":  true,
	"unspecified": true,
}

// IsUnratedSeverity reports whether a source severity carries no rating at
// all: the field is absent/blank, or the token is an explicit no-rating value.
// Tokens the vocabulary simply doesn't recognize are NOT unrated — an unknown
// word is not an assertion of unratedness. Converters use this to emit the
// shared unrated marker so a defaulted impact stays distinguishable from a
// genuine medium.
func IsUnratedSeverity(severity string) bool {
	s := strings.TrimSpace(strings.ToLower(severity))
	return s == "" || unratedSeverityTokens[s]
}
