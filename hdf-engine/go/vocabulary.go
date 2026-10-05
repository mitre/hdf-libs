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

// The forms a value has legitimately arrived under, enumerated rather than
// derived. An earlier version stripped separators to fold them together, which
// also silently repaired typos: "wai-ver" became "waiver" and "not-app-licable"
// became "notApplicable". A closed vocabulary that quietly corrects a
// misspelling is not closed — every accepted form is listed here, so accepting
// one is a decision somebody made rather than a side effect.
//
// The status and disposition entries are separator variants of one name. The
// severity entry is not: 3.7.0 renamed the bucket, and "none" is the name it had
// before, kept so a command line or spec written against the old vocabulary
// selects what it always did.
//
// Advertise records which forms help text should TEACH, so that is a property of
// the entry rather than of whichever string literal a command happens to hold.
// A separator variant is part of the CLI's display vocabulary and is taught; a
// retired name is honoured and never taught, because advertising it would hand a
// new user the name a release replaced.
type FilterAlias struct {
	Form      string
	Means     string
	Advertise bool
}

var (
	statusAliasList = []FilterAlias{
		{Form: "not_applicable", Means: string(hdf.NotApplicable), Advertise: true},
		{Form: "not_reviewed", Means: string(hdf.NotReviewed), Advertise: true},
	}
	severityAliasList = []FilterAlias{
		{Form: "none", Means: string(hdf.Informational), Advertise: false},
	}
	dispositionAliasList = []FilterAlias{
		{Form: "false_positive", Means: string(hdf.FalsePositive), Advertise: true},
	}
)

// The lookup maps are DERIVED from the lists above, so an alias cannot be
// accepted without also declaring whether it is advertised.
var (
	statusAliases      = aliasMap(statusAliasList)
	severityAliases    = aliasMap(severityAliasList)
	dispositionAliases = aliasMap(dispositionAliasList)
)

func aliasMap(aliases []FilterAlias) map[string]string {
	out := make(map[string]string, len(aliases))
	for _, a := range aliases {
		out[a.Form] = a.Means
	}
	return out
}

// FilterAliases returns the accepted non-canonical forms for a field, or nil when
// the field has no closed vocabulary.
func FilterAliases(field string) []FilterAlias {
	switch field {
	case "status":
		return statusAliasList
	case "severity":
		return severityAliasList
	case "disposition":
		return dispositionAliasList
	default:
		return nil
	}
}

// FilterValues returns the canonical vocabulary for a field, or nil when the
// field has no closed one.
func FilterValues(field string) []string {
	switch field {
	case "status":
		return StatusValues
	case "severity":
		return SeverityValues
	case "disposition":
		return DispositionValues
	default:
		return nil
	}
}

// AdvertisedFilterValues returns the forms a help string or tool schema should
// name for a field: the canonical vocabulary, then the aliases marked for
// teaching. Every value here is accepted, but not everything accepted is here —
// a retired name is deliberately absent. Callers build their own phrasing around
// this; what they must not do is keep a second hand-written list.
func AdvertisedFilterValues(field string) []string {
	canonical := FilterValues(field)
	if canonical == nil {
		return nil
	}
	// Copied from nil rather than sized by len(canonical)+len(aliases): the sum
	// is the shape go/allocation-size-overflow flags, and the capacity was only
	// an upper bound anyway because the loop below is conditional. Copying also
	// keeps the result from aliasing FilterValues' own slice, so a caller cannot
	// write through it into the vocabulary.
	out := append([]string(nil), canonical...)
	for _, a := range FilterAliases(field) {
		if a.Advertise {
			out = append(out, a.Form)
		}
	}
	return out
}

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

// ValidStatus reports whether s names a status the filter understands, in any
// accepted form. Callers validate with this and reject, rather than letting a
// typo match nothing and report a passing gate.
func ValidStatus(s string) bool { return canonical(StatusValues, statusAliases, s) != "" }

// ValidSeverity reports whether s names a severity the filter understands, in
// any accepted form.
func ValidSeverity(s string) bool { return canonical(SeverityValues, severityAliases, s) != "" }

// NormalizeFilterValue returns the canonical form of a filter value for the
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
