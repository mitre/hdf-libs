package hdfengine

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// The closed vocabularies a status or severity filter may name, in schema order.
// Options.Status and Options.Severity are matched by string equality, so a value
// outside these sets matches nothing — indistinguishable from a legitimately
// empty result. A caller validates at the boundary and refuses instead, the same
// discipline ValidImpactFilter exists for.
var (
	statusFilterValues = []string{
		string(hdf.Passed), string(hdf.Failed),
		string(hdf.NotApplicable), string(hdf.NotReviewed), string(hdf.Error),
	}
	severityFilterValues = []string{
		string(hdf.SeverityCritical), string(hdf.SeverityHigh), string(hdf.SeverityMedium),
		string(hdf.SeverityLow), string(hdf.Informational),
	}
)

// statusFilterAliases maps the extra accepted spellings onto the schema value
// they name. The snake_case forms are the CLI's display vocabulary, which saved
// command lines and agent prompts both carry.
var statusFilterAliases = map[string]string{
	"not_applicable": string(hdf.NotApplicable),
	"not_reviewed":   string(hdf.NotReviewed),
}

// severityFilterAliases carries the pre-3.7 "none" spelling of informational.
var severityFilterAliases = map[string]string{
	"none": string(hdf.Informational),
}

// StatusFilterValues returns the status values a filter may name, in schema
// order, for a caller's refusal message.
func StatusFilterValues() []string {
	return append([]string(nil), statusFilterValues...)
}

// SeverityFilterValues returns the severity values a filter may name, in schema
// order, for a caller's refusal message.
func SeverityFilterValues() []string {
	return append([]string(nil), severityFilterValues...)
}

// CanonicalStatusFilter resolves a status-filter value to the schema
// Result_Status value it names, accepting any letter case, surrounding
// whitespace, and the CLI's snake_case spellings. ok is false for an
// unrecognized value, which the caller must refuse rather than pass through.
func CanonicalStatusFilter(s string) (string, bool) {
	return canonicalFilterValue(s, statusFilterValues, statusFilterAliases)
}

// CanonicalSeverityFilter resolves a severity-filter value to the schema
// Severity value it names, accepting any letter case, surrounding whitespace,
// and the pre-3.7 "none" spelling of informational.
func CanonicalSeverityFilter(s string) (string, bool) {
	return canonicalFilterValue(s, severityFilterValues, severityFilterAliases)
}

func canonicalFilterValue(s string, values []string, aliases map[string]string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(s))
	for _, v := range values {
		if key == strings.ToLower(v) {
			return v, true
		}
	}
	if v, ok := aliases[key]; ok {
		return v, true
	}
	return "", false
}
