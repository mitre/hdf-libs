package hdfutil

import (
	"fmt"
	"strings"
)

// CVSS vector parsing and validation utilities.
//
// Supports CVSS 2.0 (legacy, no prefix), 3.0, 3.1, and 4.0 vector strings.
// Parsing is permissive; validation is strict per the FIRST grammar.
//
// References:
//   - CVSS 2.0:  https://www.first.org/cvss/v2/guide
//   - CVSS 3.1:  https://www.first.org/cvss/v3.1/specification-document
//   - CVSS 4.0:  https://www.first.org/cvss/v4.0/specification-document

// cvssMetricValues lists allowed values per metric per major version.
var cvssMetricValues = map[string]map[string][]string{
	"2.0": {
		"AV":  {"L", "A", "N"},
		"AC":  {"H", "M", "L"},
		"Au":  {"M", "S", "N"},
		"C":   {"N", "P", "C"},
		"I":   {"N", "P", "C"},
		"A":   {"N", "P", "C"},
		"E":   {"U", "POC", "F", "H", "ND"},
		"RL":  {"OF", "TF", "W", "U", "ND"},
		"RC":  {"UC", "UR", "C", "ND"},
		"CDP": {"N", "L", "LM", "MH", "H", "ND"},
		"TD":  {"N", "L", "M", "H", "ND"},
		"CR":  {"L", "M", "H", "ND"},
		"IR":  {"L", "M", "H", "ND"},
		"AR":  {"L", "M", "H", "ND"},
	},
	"3.0": cvss3xGrammar(),
	"3.1": cvss3xGrammar(),
	"4.0": {
		"AV":  {"N", "A", "L", "P"},
		"AC":  {"L", "H"},
		"AT":  {"N", "P"},
		"PR":  {"N", "L", "H"},
		"UI":  {"N", "P", "A"},
		"VC":  {"H", "L", "N"},
		"VI":  {"H", "L", "N"},
		"VA":  {"H", "L", "N"},
		"SC":  {"H", "L", "N"},
		"SI":  {"H", "L", "N"},
		"SA":  {"H", "L", "N"},
		"E":   {"X", "A", "P", "U"},
		"MAV": {"X", "N", "A", "L", "P"},
		"MAC": {"X", "L", "H"},
		"MAT": {"X", "N", "P"},
		"MPR": {"X", "N", "L", "H"},
		"MUI": {"X", "N", "P", "A"},
		"MVC": {"X", "H", "L", "N"},
		"MVI": {"X", "H", "L", "N"},
		"MVA": {"X", "H", "L", "N"},
		"MSC": {"X", "H", "L", "N"},
		"MSI": {"X", "S", "H", "L", "N"},
		"MSA": {"X", "S", "H", "L", "N"},
		"CR":  {"X", "H", "M", "L"},
		"IR":  {"X", "H", "M", "L"},
		"AR":  {"X", "H", "M", "L"},
		"S":   {"X", "N", "P"},
		"AU":  {"X", "N", "Y"},
		"R":   {"X", "A", "U", "I"},
		"V":   {"X", "D", "C"},
		"RE":  {"X", "L", "M", "H"},
		"U":   {"X", "Clear", "Green", "Amber", "Red"},
	},
}

// cvss3xGrammar returns the shared metric grammar for CVSS 3.0 and 3.1
// (the value enums are identical between the two minor versions).
func cvss3xGrammar() map[string][]string {
	return map[string][]string{
		"AV":  {"N", "A", "L", "P"},
		"AC":  {"L", "H"},
		"PR":  {"N", "L", "H"},
		"UI":  {"N", "R"},
		"S":   {"U", "C"},
		"C":   {"N", "L", "H"},
		"I":   {"N", "L", "H"},
		"A":   {"N", "L", "H"},
		"E":   {"X", "U", "P", "F", "H"},
		"RL":  {"X", "O", "T", "W", "U"},
		"RC":  {"X", "U", "R", "C"},
		"CR":  {"X", "L", "M", "H"},
		"IR":  {"X", "L", "M", "H"},
		"AR":  {"X", "L", "M", "H"},
		"MAV": {"X", "N", "A", "L", "P"},
		"MAC": {"X", "L", "H"},
		"MPR": {"X", "N", "L", "H"},
		"MUI": {"X", "N", "R"},
		"MS":  {"X", "U", "C"},
		"MC":  {"X", "N", "L", "H"},
		"MI":  {"X", "N", "L", "H"},
		"MA":  {"X", "N", "L", "H"},
	}
}

// cvssRequiredMetrics lists base metrics that must be present per version.
var cvssRequiredMetrics = map[string][]string{
	"2.0": {"AV", "AC", "Au", "C", "I", "A"},
	"3.0": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
	"3.1": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
	"4.0": {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"},
}

// ParseCvssVector splits a CVSS vector string into a version + metric map.
//
// Version detection rule: a leading "CVSS:X.Y" segment yields version "X.Y".
// Otherwise (legacy v2 vectors), version is "2.0". Malformed input yields
// version "unknown" with an empty map; the function never panics.
//
// The returned map preserves only the last value for any duplicate key.
func ParseCvssVector(vector string) (string, map[string]string) {
	metrics := map[string]string{}
	if vector == "" {
		return "unknown", metrics
	}

	// Filter out empty segments from leading/trailing slashes.
	rawSegments := strings.Split(vector, "/")
	segments := make([]string, 0, len(rawSegments))
	for _, s := range rawSegments {
		if s != "" {
			segments = append(segments, s)
		}
	}
	if len(segments) == 0 {
		return "unknown", metrics
	}

	version := "2.0"
	start := 0
	first := segments[0]
	switch {
	case strings.HasPrefix(first, "CVSS:"):
		version = strings.TrimPrefix(first, "CVSS:")
		start = 1
	case !strings.Contains(first, ":"):
		return "unknown", metrics
	}

	for i := start; i < len(segments); i++ {
		seg := segments[i]
		colon := strings.Index(seg, ":")
		if colon <= 0 || colon == len(seg)-1 {
			// Skip malformed segments (no colon, empty key, or empty value).
			continue
		}
		key := seg[:colon]
		value := seg[colon+1:]
		metrics[key] = value
	}

	return version, metrics
}

// ValidateCvssVector validates a CVSS vector against the FIRST grammar for
// its version. Returns valid=false plus a list of error messages on any
// missing required metric or out-of-enum value. Unknown metric keys are
// tolerated for forward-compatibility.
//
// Pass an empty string for the version argument to infer from the vector;
// pass an explicit version (e.g. "2.0", "3.1", "4.0") to override inference.
func ValidateCvssVector(vector, version string) (bool, []string) {
	if vector == "" {
		return false, []string{"vector is empty"}
	}

	parsedVersion, metrics := ParseCvssVector(vector)
	v := version
	if v == "" {
		v = parsedVersion
	}

	grammar, gOK := cvssMetricValues[v]
	required, rOK := cvssRequiredMetrics[v]
	if !gOK || !rOK {
		return false, []string{fmt.Sprintf("unsupported CVSS version: %s", v)}
	}

	var errs []string
	for _, req := range required {
		if _, ok := metrics[req]; !ok {
			errs = append(errs, fmt.Sprintf("missing required metric: %s", req))
		}
	}

	for key, value := range metrics {
		allowed, ok := grammar[key]
		if !ok {
			// Unknown metric: forward-compat — no error.
			continue
		}
		if !contains(allowed, value) {
			errs = append(errs, fmt.Sprintf("invalid value for metric %s: %s (allowed: %s)", key, value, strings.Join(allowed, ",")))
		}
	}

	return len(errs) == 0, errs
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
