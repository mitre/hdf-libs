package hdfutil

import (
	"fmt"
	"math"
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

// CvssScore holds computed CVSS scores for a vector.
type CvssScore struct {
	Version       string
	BaseScore     float64
	TemporalScore float64
}

// CVSS 3.1 metric weights (FIRST v3.1 specification §7). Privileges Required is
// scope-dependent, hence two tables.
var (
	cvss31AV          = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvss31AC          = map[string]float64{"L": 0.77, "H": 0.44}
	cvss31UI          = map[string]float64{"N": 0.85, "R": 0.62}
	cvss31CIA         = map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}
	cvss31PRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvss31PRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	cvss31E           = map[string]float64{"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
	cvss31RL          = map[string]float64{"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
	cvss31RC          = map[string]float64{"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
)

// ComputeCvssScore computes the CVSS 3.1 Base and Temporal (Threat) scores for a
// vector string. Only CVSS 3.1 is supported here — CVSS 4.0's MacroVector engine
// lives separately — so any other version returns an error rather than a wrong
// number. The Temporal score equals the Base score when no temporal metrics
// (E/RL/RC) are present (all default to X = 1.0), per the spec.
func ComputeCvssScore(vector string) (CvssScore, error) {
	version, m := ParseCvssVector(vector)
	if version != "3.1" {
		return CvssScore{}, fmt.Errorf("cvss: score compute supports only CVSS 3.1, got %q", version)
	}
	for _, k := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, ok := m[k]; !ok {
			return CvssScore{}, fmt.Errorf("cvss: missing required 3.1 base metric %q", k)
		}
	}
	scopeChanged := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return CvssScore{}, fmt.Errorf("cvss: invalid 3.1 Scope value %q", m["S"])
	}

	prTable := cvss31PRUnchanged
	if scopeChanged {
		prTable = cvss31PRChanged
	}
	lookup := func(table map[string]float64, key string) (float64, error) {
		v, ok := table[m[key]]
		if !ok {
			return 0, fmt.Errorf("cvss: invalid 3.1 metric value %s:%q", key, m[key])
		}
		return v, nil
	}
	av, err := lookup(cvss31AV, "AV")
	if err != nil {
		return CvssScore{}, err
	}
	ac, err := lookup(cvss31AC, "AC")
	if err != nil {
		return CvssScore{}, err
	}
	ui, err := lookup(cvss31UI, "UI")
	if err != nil {
		return CvssScore{}, err
	}
	pr, err := lookup(prTable, "PR")
	if err != nil {
		return CvssScore{}, err
	}
	c, err := lookup(cvss31CIA, "C")
	if err != nil {
		return CvssScore{}, err
	}
	i, err := lookup(cvss31CIA, "I")
	if err != nil {
		return CvssScore{}, err
	}
	a, err := lookup(cvss31CIA, "A")
	if err != nil {
		return CvssScore{}, err
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	switch {
	case impact <= 0:
		base = 0.0
	case scopeChanged:
		base = roundUp31(math.Min(1.08*(impact+exploitability), 10))
	default:
		base = roundUp31(math.Min(impact+exploitability, 10))
	}

	e, err := cvss31TemporalWeight(cvss31E, m, "E")
	if err != nil {
		return CvssScore{}, err
	}
	rl, err := cvss31TemporalWeight(cvss31RL, m, "RL")
	if err != nil {
		return CvssScore{}, err
	}
	rc, err := cvss31TemporalWeight(cvss31RC, m, "RC")
	if err != nil {
		return CvssScore{}, err
	}
	temporal := roundUp31(base * e * rl * rc)

	return CvssScore{Version: "3.1", BaseScore: base, TemporalScore: temporal}, nil
}

// cvss31TemporalWeight returns the weight for a present temporal metric, 1.0 when
// absent (defaults to X), and errors on a present-but-invalid value (no silent
// fabrication).
func cvss31TemporalWeight(table map[string]float64, m map[string]string, key string) (float64, error) {
	v, present := m[key]
	if !present {
		return 1.0, nil
	}
	if w, ok := table[v]; ok {
		return w, nil
	}
	return 0, fmt.Errorf("cvss: invalid 3.1 %s value %q", key, v)
}

// roundUp31 implements the CVSS 3.1 Roundup (spec §7.4): the smallest number, to
// one decimal place, that is >= the input — via integer math to avoid the
// floating-point edge cases the 3.0 rounding suffered.
func roundUp31(x float64) float64 {
	intInput := int(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return (math.Floor(float64(intInput)/10000) + 1) / 10.0
}
