// Package hdfutil provides shared utility functions for HDF converters and tools.
package hdfutil

import "strings"

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
