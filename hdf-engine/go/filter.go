package hdfengine

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
	// Disposition selects by the TYPE of the override that governs the
	// requirement (waiver, falsePositive, riskAdjustment, …), OR across values.
	// It is resolved through the same governing-override rule effective status
	// uses rather than read from the stored disposition field, which is an
	// output cache: a reader that trusted the cache would disagree with the
	// status it is filtering alongside.
	Disposition []string
	// Poams selects by remediation-plan validity: "valid" for a requirement
	// carrying a POA&M that is still in force, "none-valid" for one carrying
	// none, an empty list, or only lapsed ones. Absence and expiry are one
	// concept on purpose — nobody wants to know a plan exists without caring
	// whether it is still current, so a presence-only test would exist only to
	// mislead.
	Poams string
	// Now is the reference clock for expiry. Zero means time.Now(), matching
	// hdfutil's convention, so a test pins the date and production does not.
	Now      time.Time
	Limit    int
	Count    bool
	StatusOf func(control hdf.EvaluatedRequirement) string
}

// Match is a single query result row. BaselineIndex and Index are the match's
// position in the result set (results.Baselines[BaselineIndex].Requirements[Index])
// and are the only unique identity a match has: baseline names repeat in shipped
// converter output (one name for many baselines) and requirement IDs repeat
// within a baseline (one requirement per package instance), so (Baseline, ID) is
// not a key. A consumer that needs the source requirement addresses it by
// position; it must never re-derive it from the name and id.
type Match struct {
	ID            string  `json:"id"`
	Title         string  `json:"title,omitempty"`
	Status        string  `json:"status"`
	Impact        float64 `json:"impact"`
	Severity      string  `json:"severity"`
	Baseline      string  `json:"baseline"`
	BaselineIndex int     `json:"baselineIndex"`
	Index         int     `json:"index"`
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
	for bi := range results.Baselines {
		baseline := results.Baselines[bi]
		if opts.Baseline != "" && !matchesGlob(baseline.Name, opts.Baseline) {
			continue
		}
		for ri := range baseline.Requirements {
			control := baseline.Requirements[ri]
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
				ID:            control.ID,
				Title:         title,
				Status:        status,
				Impact:        control.Impact,
				Severity:      severity,
				Baseline:      baseline.Name,
				BaselineIndex: bi,
				Index:         ri,
			})
		}
	}
	return matches
}

func buildFilters(opts Options) []filterFunc {
	var filters []filterFunc

	// Status filter (OR across values). Compared through normalizeKey so the
	// CLI's display spelling and the schema's camelCase are one value: a filter
	// copied from `hdf query` and a rule written against the schema must select
	// the same requirements, or ji20j's decision 2 is not true.
	if len(opts.Status) > 0 {
		statuses := make([]string, len(opts.Status))
		for i, s := range opts.Status {
			statuses[i] = normalizeKey(NormalizeFilterValue("status", s))
		}
		filters = append(filters, func(_ hdf.EvaluatedRequirement, s, _ string) bool {
			// BOTH sides go through the same alias map. The resolver a caller
			// injects may speak the CLI's display vocabulary (not_applicable)
			// while the spec speaks the schema's (notApplicable); canonicalizing
			// the actual value as well as the requested one is what reconciles
			// them without fuzzily stripping punctuation out of typos.
			s = normalizeKey(NormalizeFilterValue("status", s))
			for _, status := range statuses {
				if s == status {
					return true
				}
			}
			return false
		})
	}

	// Severity filter (OR across values). Normalized the same way, and through
	// the alias map as well, so the pre-3.7 "none" spelling keeps naming the
	// informational severity on every surface rather than only in the CLI.
	if len(opts.Severity) > 0 {
		severities := make([]string, len(opts.Severity))
		for i, s := range opts.Severity {
			severities[i] = normalizeKey(NormalizeFilterValue("severity", s))
		}
		filters = append(filters, func(_ hdf.EvaluatedRequirement, _, severity string) bool {
			severity = normalizeKey(NormalizeFilterValue("severity", severity))
			for _, sev := range severities {
				if severity == sev {
					return true
				}
			}
			return false
		})
	}

	// Disposition filter (OR across values). Matches the governing override's
	// type; a requirement with no governing override matches nothing, which is
	// what makes "waived" and "not waived" answerable as opposites.
	if len(opts.Disposition) > 0 {
		wanted := make([]string, len(opts.Disposition))
		for i, d := range opts.Disposition {
			wanted[i] = normalizeKey(NormalizeFilterValue("disposition", d))
		}
		filters = append(filters, func(control hdf.EvaluatedRequirement, _, _ string) bool {
			governing := governingDisposition(control, opts.Now)
			if governing == "" {
				return false
			}
			for _, want := range wanted {
				if normalizeKey(NormalizeFilterValue("disposition", governing)) == want {
					return true
				}
			}
			return false
		})
	}

	// POA&M validity filter. A malformed value matches NOTHING rather than
	// silently degrading, matching the impact filter's posture — callers
	// validate with ValidPoamFilter and reject before filtering.
	if opts.Poams != "" {
		wantValid, known := poamFilterWantsValid(opts.Poams)
		filters = append(filters, func(control hdf.EvaluatedRequirement, _, _ string) bool {
			return known && hasValidPoam(control, opts.Now) == wantValid
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
	for _, s := range hdfutil.TagStrings(tags, key) {
		if strings.EqualFold(s, value) {
			return true
		}
	}
	return false
}

func tagMatchesGlob(tags map[string]any, key, pattern string) bool {
	for _, s := range hdfutil.TagStrings(tags, key) {
		if safeGlobMatch(s, pattern) {
			return true
		}
	}
	return false
}

// matchesGlob reports whether s matches the glob pattern (case-insensitive,
// timeout-protected). Thin wrapper kept for readability at call sites.
func matchesGlob(s, pattern string) bool {
	return safeGlobMatch(s, pattern)
}

// DispositionValues is the closed vocabulary the disposition filter accepts: the
// schema's Override_Type enum. A value outside it can only ever match nothing,
// which would report a clean run over a filter the caller believed was applied.
//
// Naming the generated constants pins their VALUES — a rename to risk_adjustment
// fails to compile — but not the membership: an eighth override type added to the
// schema would be silently unfilterable here, because codegen emits constants and
// not a slice to range over. Closing that needs an assertion against the bundled
// schema's enum.
var DispositionValues = []string{
	string(hdf.OverrideTypeWaiver),
	string(hdf.Attestation),
	string(hdf.Poam),
	string(hdf.Inherited),
	string(hdf.FalsePositive),
	string(hdf.RiskAdjustment),
	string(hdf.OperationalRequirement),
}

// ValidDisposition reports whether s names an override type. Callers validate
// with this and reject, rather than letting a typo match nothing and pass — the
// same contract ValidPoamFilter provides for the other amendment filter.
func ValidDisposition(s string) bool {
	return canonical(DispositionValues, dispositionAliases, s) != ""
}

// PoamValid and PoamNoneValid are the two values the poams filter accepts.
// "none-valid" covers a requirement with no POA&M, with an empty list, and with
// only lapsed ones: a plan that has expired is not a plan, and splitting the two
// cases would create a value whose only use is to be chosen by mistake.
const (
	PoamValid     = "valid"
	PoamNoneValid = "none-valid"
)

// ValidPoamFilter reports whether s is a POA&M validity value the filter
// understands. Callers validate with this and reject, rather than letting an
// unrecognized value match nothing and pass.
func ValidPoamFilter(s string) bool {
	_, known := poamFilterWantsValid(s)
	return known
}

func poamFilterWantsValid(s string) (wantValid, known bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case PoamValid:
		return true, true
	case PoamNoneValid:
		return false, true
	default:
		return false, false
	}
}

// governingDisposition returns the type of the override that governs the
// requirement, or "" when none does. The index comes from the shared
// governing-override rule — most recently applied, non-expired, carrying a
// status — so disposition and effective status can never disagree about which
// override is in force.
func governingDisposition(control hdf.EvaluatedRequirement, ref time.Time) string {
	i := hdfutil.GoverningStatusOverrideIndex(statusOverrideInputs(control.StatusOverrides), ref)
	if i < 0 {
		return ""
	}
	return string(control.StatusOverrides[i].Type)
}

// hasValidPoam reports whether the requirement carries a POA&M that is still in
// force. expiresAt is required by the schema, so a POA&M always has a deadline
// to judge; one exactly at the reference instant has passed, matching how an
// override's expiry is judged.
func hasValidPoam(control hdf.EvaluatedRequirement, ref time.Time) bool {
	if ref.IsZero() {
		ref = time.Now()
	}
	for _, poam := range control.Poams {
		if poam.ExpiresAt.After(ref) {
			return true
		}
	}
	return false
}

// statusOverrideInputs maps schema overrides onto the shared helper's neutral
// shape. It is the sixth copy of this mapping in the repo, not the second —
// hdf-converters/shared/go/status.go and .../exportmap, hdf-diff/go/status.go and
// .../effective_checksum.go, and compliance_test.go in this package all carry it.
// The cause is structural: hdfutil owns the neutral shape but cannot take a schema
// type (it is a schema-free leaf), and the modules that hold both sides depend on
// hdfutil rather than on each other. Consolidating needs a schema-typed adapter
// every one of them can reach, which is a repo-wide change and not this card's.
func statusOverrideInputs(overrides []hdf.StatusOverride) []hdfutil.StatusOverrideInput {
	inputs := make([]hdfutil.StatusOverrideInput, len(overrides))
	for i, o := range overrides {
		inputs[i] = hdfutil.StatusOverrideInput{AppliedAt: o.AppliedAt, ExpiresAt: o.ExpiresAt}
		if o.Status != nil {
			inputs[i].Status = string(*o.Status)
		}
	}
	return inputs
}
