package hdfutil

import (
	_ "embed"
	"encoding/json"
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

// --- CVSS 4.0 scoring (MacroVector engine) ---
//
// A faithful port of the FIRST reference calculator (FIRSTdotorg/cvss-v4-calculator:
// cvss_score.js), driven by the MacroVector lookup + max tables extracted verbatim
// into cvss40-data.json. The TypeScript peer (src/cvss/index.ts) is kept
// byte-identical via the shared data file and the shared parity fixture.

//go:embed cvss40-data.json
var cvss40DataRaw []byte

type cvss40Tables struct {
	Lookup      map[string]float64 `json:"lookup"`
	MaxComposed struct {
		Eq1 map[string][]string            `json:"eq1"`
		Eq2 map[string][]string            `json:"eq2"`
		Eq3 map[string]map[string][]string `json:"eq3"`
		Eq4 map[string][]string            `json:"eq4"`
		Eq5 map[string][]string            `json:"eq5"`
	} `json:"maxComposed"`
	MaxSeverity struct {
		Eq1    map[string]int            `json:"eq1"`
		Eq2    map[string]int            `json:"eq2"`
		Eq3eq6 map[string]map[string]int `json:"eq3eq6"`
		Eq4    map[string]int            `json:"eq4"`
		Eq5    map[string]int            `json:"eq5"`
	} `json:"maxSeverity"`
}

var cvss40 = mustLoadCvss40()

func mustLoadCvss40() cvss40Tables {
	var t cvss40Tables
	if err := json.Unmarshal(cvss40DataRaw, &t); err != nil {
		panic(fmt.Sprintf("cvss: cannot parse embedded cvss40-data.json: %v", err))
	}
	return t
}

// Per-metric severity index tables (FIRST reference cvss_score.js). Lower = worse.
var (
	cvss40AVLevels = map[string]float64{"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
	cvss40PRLevels = map[string]float64{"N": 0.0, "L": 0.1, "H": 0.2}
	cvss40UILevels = map[string]float64{"N": 0.0, "P": 0.1, "A": 0.2}
	cvss40ACLevels = map[string]float64{"L": 0.0, "H": 0.1}
	cvss40ATLevels = map[string]float64{"N": 0.0, "P": 0.1}
	cvss40VCLevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	cvss40SCLevels = map[string]float64{"H": 0.1, "L": 0.2, "N": 0.3}
	cvss40SILevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
	cvss40CRLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
)

// cvss40Metric resolves the effective value of a metric, mirroring the reference
// m(): E:X and unset default to A (worst case); CR/IR/AR:X and unset default to
// H; a present, non-X Modified metric (M-prefixed) overrides its base.
func cvss40Metric(sel map[string]string, metric string) string {
	selected := sel[metric]
	switch metric {
	case "E":
		if selected == "" || selected == "X" {
			return "A"
		}
	case "CR", "IR", "AR":
		if selected == "" || selected == "X" {
			return "H"
		}
	}
	if mod, ok := sel["M"+metric]; ok && mod != "X" {
		return mod
	}
	return selected
}

// cvss40MacroVectorFromSel derives the six-digit MacroVector (EQ1–EQ6).
func cvss40MacroVectorFromSel(sel map[string]string) string {
	mv := func(k string) string { return cvss40Metric(sel, k) }

	// EQ1 (the "not all three N" term of the reference's level-1 clause is
	// redundant here: level 0 already consumes the all-three-N case).
	eq1 := "2"
	switch {
	case mv("AV") == "N" && mv("PR") == "N" && mv("UI") == "N":
		eq1 = "0"
	case (mv("AV") == "N" || mv("PR") == "N" || mv("UI") == "N") && mv("AV") != "P":
		eq1 = "1"
	}

	// EQ2
	eq2 := "1"
	if mv("AC") == "L" && mv("AT") == "N" {
		eq2 = "0"
	}

	// EQ3
	eq3 := "2"
	switch {
	case mv("VC") == "H" && mv("VI") == "H":
		eq3 = "0"
	case mv("VC") == "H" || mv("VI") == "H" || mv("VA") == "H":
		eq3 = "1"
	}

	// EQ4
	eq4 := "2"
	switch {
	case mv("MSI") == "S" || mv("MSA") == "S":
		eq4 = "0"
	case mv("SC") == "H" || mv("SI") == "H" || mv("SA") == "H":
		eq4 = "1"
	}

	// EQ5
	eq5 := "2"
	switch mv("E") {
	case "A":
		eq5 = "0"
	case "P":
		eq5 = "1"
	}

	// EQ6
	eq6 := "1"
	if (mv("CR") == "H" && mv("VC") == "H") ||
		(mv("IR") == "H" && mv("VI") == "H") ||
		(mv("AR") == "H" && mv("VA") == "H") {
		eq6 = "0"
	}

	return eq1 + eq2 + eq3 + eq4 + eq5 + eq6
}

// Cvss40MacroVector parses a CVSS 4.0 vector and returns its MacroVector string.
func Cvss40MacroVector(vector string) string {
	_, m := ParseCvssVector(vector)
	return cvss40MacroVectorFromSel(m)
}

// cvss40ExtractMetric pulls a metric's value out of a composed max-vector string
// (e.g. "AV:N/PR:N/UI:N/…"), mirroring the reference extractValueMetric().
func cvss40ExtractMetric(metric, s string) string {
	idx := strings.Index(s, metric)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(metric)+1:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[:slash]
	}
	return rest
}

// cvss40ScoreForVector computes the single FIRST 4.0 score for a parsed vector.
// Faithful port of cvss_score.js.
func cvss40ScoreForVector(vector string) float64 {
	_, sel := ParseCvssVector(vector)
	return cvss40Score(sel)
}

func cvss40Score(sel map[string]string) float64 {
	mv := func(k string) string { return cvss40Metric(sel, k) }

	// Shortcut: no impact on any system.
	if mv("VC") == "N" && mv("VI") == "N" && mv("VA") == "N" &&
		mv("SC") == "N" && mv("SI") == "N" && mv("SA") == "N" {
		return 0.0
	}

	macro := cvss40MacroVectorFromSel(sel)
	value := cvss40.Lookup[macro]

	eq1 := int(macro[0] - '0')
	eq3 := int(macro[2] - '0')
	eq6 := int(macro[5] - '0')

	eq1NextLower := fmt.Sprintf("%d%c%c%c%c%c", eq1+1, macro[1], macro[2], macro[3], macro[4], macro[5])
	eq2NextLower := fmt.Sprintf("%c%d%c%c%c%c", macro[0], int(macro[1]-'0')+1, macro[2], macro[3], macro[4], macro[5])
	eq4NextLower := fmt.Sprintf("%c%c%c%d%c%c", macro[0], macro[1], macro[2], int(macro[3]-'0')+1, macro[4], macro[5])
	eq5NextLower := fmt.Sprintf("%c%c%c%c%d%c", macro[0], macro[1], macro[2], macro[3], int(macro[4]-'0')+1, macro[5])

	// eq3 and eq6 are coupled — their combined next-lower macro depends on both.
	availDistEq3eq6 := math.NaN()
	switch {
	case eq3 == 1 && eq6 == 1:
		availDistEq3eq6 = availDist(value, fmt.Sprintf("%c%c%d%c%c%c", macro[0], macro[1], eq3+1, macro[3], macro[4], macro[5]))
	case eq3 == 0 && eq6 == 1:
		availDistEq3eq6 = availDist(value, fmt.Sprintf("%c%c%d%c%c%c", macro[0], macro[1], eq3+1, macro[3], macro[4], macro[5]))
	case eq3 == 1 && eq6 == 0:
		availDistEq3eq6 = availDist(value, fmt.Sprintf("%c%c%c%c%c%d", macro[0], macro[1], macro[2], macro[3], macro[4], eq6+1))
	case eq3 == 0 && eq6 == 0:
		// Two possible paths; take the one with the higher lower-macro score.
		left, okL := cvss40.Lookup[fmt.Sprintf("%c%c%c%c%c%d", macro[0], macro[1], macro[2], macro[3], macro[4], eq6+1)]
		right, okR := cvss40.Lookup[fmt.Sprintf("%c%c%d%c%c%c", macro[0], macro[1], eq3+1, macro[3], macro[4], macro[5])]
		switch {
		case okL && okR:
			availDistEq3eq6 = value - math.Max(left, right)
		case okR:
			availDistEq3eq6 = value - right
		}
	default:
		availDistEq3eq6 = availDist(value, fmt.Sprintf("%c%c%d%c%c%d", macro[0], macro[1], eq3+1, macro[3], macro[4], eq6+1))
	}

	availDistEq1 := availDist(value, eq1NextLower)
	availDistEq2 := availDist(value, eq2NextLower)
	availDistEq4 := availDist(value, eq4NextLower)
	availDistEq5 := availDist(value, eq5NextLower)

	// Compose the highest-severity vectors for this MacroVector.
	eq1Maxes := cvss40.MaxComposed.Eq1[string(macro[0])]
	eq2Maxes := cvss40.MaxComposed.Eq2[string(macro[1])]
	eq3eq6Maxes := cvss40.MaxComposed.Eq3[string(macro[2])][string(macro[5])]
	eq4Maxes := cvss40.MaxComposed.Eq4[string(macro[3])]
	eq5Maxes := cvss40.MaxComposed.Eq5[string(macro[4])]

	maxVectors := make([]string, 0, len(eq1Maxes)*len(eq2Maxes)*len(eq3eq6Maxes)*len(eq4Maxes)*len(eq5Maxes))
	for _, a := range eq1Maxes {
		for _, b := range eq2Maxes {
			for _, c := range eq3eq6Maxes {
				for _, e := range eq4Maxes {
					for _, f := range eq5Maxes {
						maxVectors = append(maxVectors, a+b+c+e+f)
					}
				}
			}
		}
	}

	// Find a max-vector no less severe (per-metric) than the scored vector.
	var sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR float64
	for _, maxVector := range maxVectors {
		sdAV = cvss40AVLevels[mv("AV")] - cvss40AVLevels[cvss40ExtractMetric("AV", maxVector)]
		sdPR = cvss40PRLevels[mv("PR")] - cvss40PRLevels[cvss40ExtractMetric("PR", maxVector)]
		sdUI = cvss40UILevels[mv("UI")] - cvss40UILevels[cvss40ExtractMetric("UI", maxVector)]
		sdAC = cvss40ACLevels[mv("AC")] - cvss40ACLevels[cvss40ExtractMetric("AC", maxVector)]
		sdAT = cvss40ATLevels[mv("AT")] - cvss40ATLevels[cvss40ExtractMetric("AT", maxVector)]
		sdVC = cvss40VCLevels[mv("VC")] - cvss40VCLevels[cvss40ExtractMetric("VC", maxVector)]
		sdVI = cvss40VCLevels[mv("VI")] - cvss40VCLevels[cvss40ExtractMetric("VI", maxVector)]
		sdVA = cvss40VCLevels[mv("VA")] - cvss40VCLevels[cvss40ExtractMetric("VA", maxVector)]
		sdSC = cvss40SCLevels[mv("SC")] - cvss40SCLevels[cvss40ExtractMetric("SC", maxVector)]
		sdSI = cvss40SILevels[mv("SI")] - cvss40SILevels[cvss40ExtractMetric("SI", maxVector)]
		sdSA = cvss40SILevels[mv("SA")] - cvss40SILevels[cvss40ExtractMetric("SA", maxVector)]
		sdCR = cvss40CRLevels[mv("CR")] - cvss40CRLevels[cvss40ExtractMetric("CR", maxVector)]
		sdIR = cvss40CRLevels[mv("IR")] - cvss40CRLevels[cvss40ExtractMetric("IR", maxVector)]
		sdAR = cvss40CRLevels[mv("AR")] - cvss40CRLevels[cvss40ExtractMetric("AR", maxVector)]
		if anyNegative(sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR) {
			continue
		}
		break
	}

	curEq1 := sdAV + sdPR + sdUI
	curEq2 := sdAC + sdAT
	curEq3eq6 := sdVC + sdVI + sdVA + sdCR + sdIR + sdAR
	curEq4 := sdSC + sdSI + sdSA

	const step = 0.1
	maxSevEq1 := float64(cvss40.MaxSeverity.Eq1[string(macro[0])]) * step
	maxSevEq2 := float64(cvss40.MaxSeverity.Eq2[string(macro[1])]) * step
	maxSevEq3eq6 := float64(cvss40.MaxSeverity.Eq3eq6[string(macro[2])][string(macro[5])]) * step
	maxSevEq4 := float64(cvss40.MaxSeverity.Eq4[string(macro[3])]) * step

	nExisting := 0
	var normEq1, normEq2, normEq3eq6, normEq4, normEq5 float64
	if !math.IsNaN(availDistEq1) {
		nExisting++
		normEq1 = availDistEq1 * (curEq1 / maxSevEq1)
	}
	if !math.IsNaN(availDistEq2) {
		nExisting++
		normEq2 = availDistEq2 * (curEq2 / maxSevEq2)
	}
	if !math.IsNaN(availDistEq3eq6) {
		nExisting++
		normEq3eq6 = availDistEq3eq6 * (curEq3eq6 / maxSevEq3eq6)
	}
	if !math.IsNaN(availDistEq4) {
		nExisting++
		normEq4 = availDistEq4 * (curEq4 / maxSevEq4)
	}
	if !math.IsNaN(availDistEq5) {
		nExisting++
		normEq5 = 0 // eq5 proportion is always 0 per the reference
	}

	meanDistance := 0.0
	if nExisting > 0 {
		meanDistance = (normEq1 + normEq2 + normEq3eq6 + normEq4 + normEq5) / float64(nExisting)
	}

	value -= meanDistance
	if value < 0 {
		value = 0.0
	}
	if value > 10 {
		value = 10.0
	}
	return math.Round(value*10) / 10
}

// availDist returns value minus the lower macro's score, or NaN when that lower
// macro does not exist (the reference's isNaN sentinel).
func availDist(value float64, lowerMacro string) float64 {
	if s, ok := cvss40.Lookup[lowerMacro]; ok {
		return value - s
	}
	return math.NaN()
}

func anyNegative(vals ...float64) bool {
	for _, v := range vals {
		if v < 0 {
			return true
		}
	}
	return false
}

// ComputeCvss40Score computes the CVSS 4.0 score for a vector string, splitting
// it into a Base score (BaseScore, computed with Exploit Maturity stripped to its
// worst-case default E:A) and a Threat score (TemporalScore, computed with the E
// value present in the vector). For a base-only vector the two are equal. Only
// CVSS 4.0 vectors are accepted; any other version, a missing required base
// metric, or an out-of-enum value returns an error (never a fabricated number).
func ComputeCvss40Score(vector string) (CvssScore, error) {
	version, _ := ParseCvssVector(vector)
	if version != "4.0" {
		return CvssScore{}, fmt.Errorf("cvss: 4.0 score compute supports only CVSS 4.0, got %q", version)
	}
	if valid, errs := ValidateCvssVector(vector, "4.0"); !valid {
		return CvssScore{}, fmt.Errorf("cvss: invalid 4.0 vector: %s", strings.Join(errs, "; "))
	}

	temporal := cvss40ScoreForVector(vector)
	base := cvss40ScoreForVector(cvss40StripExploitMaturity(vector))
	return CvssScore{Version: "4.0", BaseScore: base, TemporalScore: temporal}, nil
}

// cvss40StripExploitMaturity removes the E: segment so the Base score reflects
// the worst-case default (E:X, treated as E:A).
func cvss40StripExploitMaturity(vector string) string {
	segs := strings.Split(vector, "/")
	out := segs[:0]
	for _, s := range segs {
		if strings.HasPrefix(s, "E:") {
			continue
		}
		out = append(out, s)
	}
	return strings.Join(out, "/")
}
