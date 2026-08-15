package hdfengine

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// decimalFloat is the shared impact-filter operand grammar: a plain decimal —
// optional sign, digits with an optional fraction (or a leading-dot fraction),
// optional decimal exponent. It deliberately excludes the forms strconv.ParseFloat
// also accepts but that make no sense as a 0.0–1.0 threshold and diverge from JS
// Number(): hex-floats (0x1p-2), digit-separator underscores (1_000), and
// Inf/NaN. The TS engine applies the identical pattern so a filter is accepted
// or rejected the same in both languages (bead 4908.15).
var decimalFloat = regexp.MustCompile(`^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$`)

// Options configures a requirements query. Every filter input arrives here — the
// engine reads no package-level state, so Filter is re-entrant and safe to call
// concurrently. Distinct filters combine with AND; repeated values within a
// single filter combine with OR.
//
// StatusOf resolves a requirement's display status. It is injected so the engine
// stays agnostic to the caller's status-string convention (the CLI passes its
// determineControlStatus; another consumer may map statuses differently). When
// nil, the resolved status is the empty string.
type Options struct {
	Status   []string
	Severity []string
	Impact   string
	CCI      []string
	NIST     []string
	ID       string
	Tag      []string
	Search   string
	Baseline string
	Limit    int
	Count    bool
	StatusOf func(control hdf.EvaluatedRequirement) string
}

// Match is a single query result row.
type Match struct {
	ID       string  `json:"id"`
	Title    string  `json:"title,omitempty"`
	Status   string  `json:"status"`
	Impact   float64 `json:"impact"`
	Severity string  `json:"severity"`
	Baseline string  `json:"baseline"`
}

type filterFunc func(control hdf.EvaluatedRequirement, status, severity string) bool

// Filter returns the requirements across the result set's baselines that satisfy
// opts. It applies to requirement collections (results/baseline documents); the
// calling adapter is responsible for rejecting document types that carry no
// requirements.
//
// ctx cancellation is honored at per-requirement granularity: a cancelled ctx
// stops the scan and returns the matches gathered so far, so a caller (or the
// Tasks executor) can abort a large query. The caller checks ctx.Err() to
// distinguish a cancelled partial result from a complete one.
func Filter(ctx context.Context, results hdf.HDFResults, opts Options) []Match {
	filters := buildFilters(opts)

	var matches []Match
	for _, baseline := range results.Baselines {
		if opts.Baseline != "" && !matchesGlob(baseline.Name, opts.Baseline) {
			continue
		}
		for _, control := range baseline.Requirements {
			if ctx.Err() != nil {
				return matches
			}
			if opts.Limit > 0 && len(matches) >= opts.Limit && !opts.Count {
				return matches
			}

			status := ""
			if opts.StatusOf != nil {
				status = opts.StatusOf(control)
			}
			// Explicit STIG severity wins; impact-derived only as a fallback — one
			// canonical rule (DeriveSeverity) shared with the compliance counts, so
			// hdf_query and hdf_compliance never disagree on a requirement's severity.
			severity := DeriveSeverity(control.Impact, control.Severity)

			if !applyFilters(control, status, severity, filters) {
				continue
			}

			title := ""
			if control.Title != nil {
				title = *control.Title
			}
			matches = append(matches, Match{
				ID:       control.ID,
				Title:    title,
				Status:   status,
				Impact:   control.Impact,
				Severity: severity,
				Baseline: baseline.Name,
			})
		}
	}
	return matches
}

func buildFilters(opts Options) []filterFunc {
	var filters []filterFunc

	// Status filter (OR across values)
	if len(opts.Status) > 0 {
		statuses := make([]string, len(opts.Status))
		for i, s := range opts.Status {
			statuses[i] = strings.ToLower(s)
		}
		filters = append(filters, func(_ hdf.EvaluatedRequirement, s, _ string) bool {
			s = strings.ToLower(s)
			for _, status := range statuses {
				if s == status {
					return true
				}
			}
			return false
		})
	}

	// Severity filter (OR across values)
	if len(opts.Severity) > 0 {
		severities := make([]string, len(opts.Severity))
		for i, s := range opts.Severity {
			severities[i] = strings.ToLower(s)
		}
		filters = append(filters, func(_ hdf.EvaluatedRequirement, _, severity string) bool {
			for _, sev := range severities {
				if severity == sev {
					return true
				}
			}
			return false
		})
	}

	// Impact filter (supports >, >=, <, <=, =). A malformed filter matches
	// NOTHING rather than silently degrading to impact==0 — callers should
	// validate with ValidImpactFilter and reject before filtering.
	if opts.Impact != "" {
		op, val, ok := parseImpactFilter(opts.Impact)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return ok && compareImpact(c.Impact, op, val)
		})
	}

	// CCI filter (OR across values)
	if len(opts.CCI) > 0 {
		ccis := make([]string, len(opts.CCI))
		for i, c := range opts.CCI {
			ccis[i] = strings.ToUpper(c)
		}
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			for _, cci := range ccis {
				if tagContains(c.Tags, "cci", cci) {
					return true
				}
			}
			return false
		})
	}

	// NIST filter (OR across values)
	if len(opts.NIST) > 0 {
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			for _, nist := range opts.NIST {
				if tagMatchesGlob(c.Tags, "nist", nist) {
					return true
				}
			}
			return false
		})
	}

	// ID filter (requirement ID / STIG ID / GID / group title)
	if opts.ID != "" {
		id := opts.ID
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return tagContains(c.Tags, "stig_id", id) ||
				tagContains(c.Tags, "gid", id) ||
				tagContains(c.Tags, "gtitle", id) ||
				c.ID == id
		})
	}

	// Generic tag filter (OR across values)
	if len(opts.Tag) > 0 {
		type tagFilter struct {
			key, value string
		}
		var tagFilters []tagFilter
		for _, t := range opts.Tag {
			parts := strings.SplitN(t, ":", 2)
			if len(parts) == 2 {
				tagFilters = append(tagFilters, tagFilter{key: parts[0], value: parts[1]})
			}
		}
		if len(tagFilters) > 0 {
			filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
				for _, tf := range tagFilters {
					if tagMatchesGlob(c.Tags, tf.key, tf.value) {
						return true
					}
				}
				return false
			})
		}
	}

	// Text search filter
	if opts.Search != "" {
		search := strings.ToLower(opts.Search)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			if strings.Contains(strings.ToLower(c.ID), search) {
				return true
			}
			if c.Title != nil && strings.Contains(strings.ToLower(*c.Title), search) {
				return true
			}
			for _, desc := range c.Descriptions {
				if strings.Contains(strings.ToLower(desc.Data), search) {
					return true
				}
			}
			return false
		})
	}

	return filters
}

func applyFilters(control hdf.EvaluatedRequirement, status, severity string, filters []filterFunc) bool {
	for _, f := range filters {
		if !f(control, status, severity) {
			return false
		}
	}
	return true
}

// parseImpactFilter parses a comparison filter (e.g. ">0.5", "=0", "0.7"). ok is
// false when the operand does not parse as a number — the caller must treat that
// as an invalid filter, NOT coerce it to a predicate (silently degrading a typo
// to impact==0 returned confidently-wrong rows).
func parseImpactFilter(filter string) (op string, val float64, ok bool) {
	filter = strings.TrimSpace(filter)

	operators := []string{">=", "<=", ">", "<", "="}
	for _, o := range operators {
		if strings.HasPrefix(filter, o) {
			v, ok := parseDecimal(strings.TrimSpace(filter[len(o):]))
			if !ok {
				return "", 0, false
			}
			return o, v, true
		}
	}

	v, ok := parseDecimal(filter)
	if !ok {
		return "", 0, false
	}
	return "=", v, true
}

// parseDecimal parses a plain-decimal operand, rejecting the non-decimal forms
// strconv.ParseFloat would otherwise accept (see decimalFloat). The ParseFloat
// call still runs so overflow to ±Inf (ErrRange, e.g. "1e400") is rejected too.
func parseDecimal(s string) (float64, bool) {
	if !decimalFloat.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ValidImpactFilter reports whether s is a well-formed impact comparison filter
// (a comparator plus a number, or a bare number). Callers validate at the
// boundary and reject a malformed filter rather than let it match nothing.
func ValidImpactFilter(s string) bool {
	_, _, ok := parseImpactFilter(s)
	return ok
}

func compareImpact(impact float64, op string, val float64) bool {
	switch op {
	case ">":
		return impact > val
	case ">=":
		return impact >= val
	case "<":
		return impact < val
	case "<=":
		return impact <= val
	case "=":
		return impact == val
	default:
		return false
	}
}

func tagContains(tags map[string]any, key, value string) bool {
	if tags == nil {
		return false
	}
	tagVal, ok := tags[key]
	if !ok {
		return false
	}
	switch v := tagVal.(type) {
	case string:
		return strings.EqualFold(v, value)
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok {
				if strings.EqualFold(str, value) {
					return true
				}
			}
		}
	case []string:
		for _, str := range v {
			if strings.EqualFold(str, value) {
				return true
			}
		}
	}
	return false
}

func tagMatchesGlob(tags map[string]any, key, pattern string) bool {
	if tags == nil {
		return false
	}
	tagVal, ok := tags[key]
	if !ok {
		return false
	}
	switch v := tagVal.(type) {
	case string:
		return safeGlobMatch(v, pattern)
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok {
				if safeGlobMatch(str, pattern) {
					return true
				}
			}
		}
	case []string:
		for _, str := range v {
			if safeGlobMatch(str, pattern) {
				return true
			}
		}
	}
	return false
}

// matchesGlob reports whether s matches the glob pattern (case-insensitive,
// timeout-protected). Thin wrapper kept for readability at call sites.
func matchesGlob(s, pattern string) bool {
	return safeGlobMatch(s, pattern)
}
