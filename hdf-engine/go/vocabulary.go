package hdfengine

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// StatusValues is the closed vocabulary a status filter may name: the schema's
// Result_Status enum. It is the EFFECTIVE status that is compared — the resolver
// a caller injects runs the override ladder first — so these are the values a
// requirement can present after its amendments are applied.
var StatusValues = []string{
	string(hdf.Passed),
	string(hdf.Failed),
	string(hdf.NotApplicable),
	string(hdf.NotReviewed),
	string(hdf.Error),
}

// SeverityValues is the closed vocabulary a severity filter may name: the
// schema's Severity enum, which is also what DeriveSeverity returns.
var SeverityValues = []string{
	string(hdf.SeverityCritical),
	string(hdf.SeverityHigh),
	string(hdf.SeverityMedium),
	string(hdf.SeverityLow),
	string(hdf.Informational),
}

// The spellings a value has legitimately arrived under, enumerated rather than
// derived. An earlier version stripped separators to fold spellings together,
// which also silently repaired typos: "wai-ver" became "waiver" and
// "not-app-licable" became "notApplicable". A closed vocabulary that quietly
// corrects a misspelling is not closed — every accepted spelling is listed here,
// so accepting one is a decision somebody made rather than a side effect.
var (
	statusAliases = map[string]string{
		"not_applicable": string(hdf.NotApplicable),
		"not_reviewed":   string(hdf.NotReviewed),
	}
	severityAliases    = map[string]string{"none": string(hdf.Informational)}
	dispositionAliases = map[string]string{"false_positive": string(hdf.FalsePositive)}
)

// normalizeKey folds a value to the form comparisons use. Case only: two
// spellings are the same value because this file says so, not because enough
// punctuation was removed to make them collide.
func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// canonical returns the vocabulary member a value names, or "" when none does.
func canonical(vocabulary []string, aliases map[string]string, value string) string {
	key := normalizeKey(value)
	if aliases != nil {
		if target, ok := aliases[key]; ok {
			return target
		}
	}
	for _, member := range vocabulary {
		if normalizeKey(member) == key {
			return member
		}
	}
	return ""
}

// ValidStatus reports whether s names a status the filter understands, under any
// accepted spelling. Callers validate with this and reject, rather than letting a
// typo match nothing and report a passing gate.
func ValidStatus(s string) bool { return canonical(StatusValues, statusAliases, s) != "" }

// ValidSeverity reports whether s names a severity the filter understands, under
// any accepted spelling.
func ValidSeverity(s string) bool { return canonical(SeverityValues, severityAliases, s) != "" }

// NormalizeFilterValue returns the canonical spelling of a filter value for the
// named field, or the value unchanged when the field has no closed vocabulary or
// the value names no member. Normalizing here rather than in one caller is what
// makes a threshold rule and an `hdf query` invocation mean the same thing.
func NormalizeFilterValue(field, value string) string {
	var got string
	switch field {
	case "status":
		got = canonical(StatusValues, statusAliases, value)
	case "severity":
		got = canonical(SeverityValues, severityAliases, value)
	case "disposition":
		got = canonical(DispositionValues, dispositionAliases, value)
	case "poams":
		if wantValid, known := poamFilterWantsValid(value); known {
			if wantValid {
				return PoamValid
			}
			return PoamNoneValid
		}
	}
	if got == "" {
		return value
	}
	return got
}
