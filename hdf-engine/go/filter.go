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
	Status   Values
	Severity Values
	// Impact compares the EFFECTIVE impact — the governing non-expired impact
	// override's value, else the requirement's own.
	Impact string
	// RawImpact compares the requirement's own impact, ignoring overrides. It
	// exists because Impact resolves them: the governance policy "an override
	// may not move a critical below 0.7" needs both scores, and no other key
	// reaches the unadjusted one.
	RawImpact string
	// Cvss compares the requirement's authoritative CVSS score, using the same
	// comparison grammar as Impact. See cvssScoreOf for what "authoritative"
	// resolves to and how several CVSS entries collapse to one number.
	Cvss string
	// Epss compares the EPSS exploit PROBABILITY (epss.score), not the
	// percentile rank. They share a 0-1 scale and mean very different things.
	Epss string
	// Kev selects on CISA Known Exploited Vulnerabilities membership: "true" for
	// kev.inKev, "false" for everything else — including a requirement carrying
	// no kev block at all, which is not known-exploited either.
	Kev string
	// Cwe selects by CWE identifier, OR across values, matched numerically so
	// CWE-79, "CWE 79" and cwe79 are one value. It reads the first-class cwe[]
	// field ONLY and never falls back to tags.cwe, so the filter means the same
	// thing on every document.
	Cwe      Values
	CCI      Values
	NIST     Values
	ID       string
	Tag      Values
	Search   string
	Baseline string
	// BaselineLabel selects requirements by the labels of the baseline they sit
	// in, as "key:value", OR across values, with the value globbable exactly as a
	// tag value is. Named for the baseline rather than "label" alone because
	// there is no requirement-level label, and because system documents carry
	// component labels that may one day want their own key.
	//
	// A label is a property of the BASELINE, so this is applied once per baseline
	// beside Baseline rather than per requirement. A baseline carrying no labels
	// therefore matches nothing: an absent label is not a wildcard.
	BaselineLabel Values
	// Disposition selects by the TYPE of the override that governs the
	// requirement (waiver, falsePositive, riskAdjustment, …), OR across values.
	// The governing override is the most recent non-expired one of ANY kind, so
	// it may differ from the one that set the status — see governingDisposition.
	// Resolved rather than read from the stored disposition field, which is an
	// output cache: a reader that trusted the cache would disagree with the
	// status it is filtering alongside.
	Disposition Values
	// Poams selects by remediation-plan validity: "valid" for a requirement
	// carrying a POA&M that is still in force, "none-valid" for one carrying
	// none, an empty list, or only lapsed ones. Absence and expiry are one
	// concept on purpose — nobody wants to know a plan exists without caring
	// whether it is still current, so a presence-only test would exist only to
	// mislead.
	Poams string
	// PoamType selects by the KIND of the governing POA&M — remediation,
	// mitigation, riskAcceptance or vendorDependency. It exists because
	// disposition is typed Override_Type and collapses every governing plan to
	// the flat "poam", so the four kinds are otherwise indistinguishable. A
	// separate key rather than a subtype spelling inside disposition: the four
	// are not override types, and a punctuation-joined value would either borrow
	// the label separator (signalling a key=value pair for a typed enum) or add a
	// second separator to files that already use one.
	PoamType Values
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
		if !baselineLabelsMatch(baseline.Labels, opts.BaselineLabel) {
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
			// Effective impact for the same reason the impact filter uses it: a
			// governing riskAdjustment moves the requirement into the band it
			// was re-scored into, and Filter is an override-aware surface.
			impact := EffectiveImpactOf(control, opts.Now)
			severity := DeriveSeverity(impact, control.Severity)

			if !applyFilters(control, status, severity, filters) {
				continue
			}

			title := ""
			if control.Title != nil {
				title = *control.Title
			}
			matches = append(matches, Match{
				ID:     control.ID,
				Title:  title,
				Status: status,
				// The effective impact, for the same reason Status carries the
				// effective status and a Match has no raw twin of either.
				Impact:        impact,
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
	if opts.Status.Active() {
		filters = append(filters, func(_ hdf.EvaluatedRequirement, s, _ string) bool {
			// BOTH sides go through the same alias map. The resolver a caller
			// injects may speak the CLI's display vocabulary (not_applicable)
			// while the spec speaks the schema's (notApplicable); canonicalizing
			// the actual value as well as the requested one is what reconciles
			// them without fuzzily stripping punctuation out of typos.
			actual := normalizeKey(NormalizeFilterValue("status", s))
			return opts.Status.Match(func(want string) bool {
				return actual == normalizeKey(NormalizeFilterValue("status", want))
			})
		})
	}

	// Severity filter (OR across values). Normalized the same way, and through
	// the alias map as well, so "none" — the name informational replaced in
	// 3.7.0 — keeps selecting it on every surface, not only in the CLI.
	if opts.Severity.Active() {
		filters = append(filters, func(_ hdf.EvaluatedRequirement, _, severity string) bool {
			actual := normalizeKey(NormalizeFilterValue("severity", severity))
			return opts.Severity.Match(func(want string) bool {
				return actual == normalizeKey(NormalizeFilterValue("severity", want))
			})
		})
	}

	// Disposition filter (OR across values). Matches the governing override's
	// type; a requirement with no governing override matches nothing, which is
	// what makes "waived" and "not waived" answerable as opposites.
	if opts.Disposition.Active() {
		filters = append(filters, func(control hdf.EvaluatedRequirement, _, _ string) bool {
			governing := governingDisposition(control, opts.Now)
			// Nothing governing matches no VALUE, which is what makes an
			// inclusive predicate exclude it and a negation accept it — a
			// failure nobody adjudicated is correctly "not waived".
			actual := normalizeKey(NormalizeFilterValue("disposition", governing))
			return opts.Disposition.Match(func(want string) bool {
				return governing != "" && actual == normalizeKey(NormalizeFilterValue("disposition", want))
			})
		})
	}

	if opts.PoamType.Active() {
		filters = append(filters, func(control hdf.EvaluatedRequirement, _, _ string) bool {
			kind := governingPoamType(control, opts.Now)
			return opts.PoamType.Match(func(want string) bool {
				return kind != "" && normalizeKey(kind) == normalizeKey(want)
			})
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
	//
	// Compared against EFFECTIVE impact, so a governing riskAdjustment is
	// honoured. Status has resolved overrides all along; an impact filter that
	// ignored a formal re-score was the same amendments-blindness in the field
	// nobody looked at.
	if opts.Impact != "" {
		now := opts.Now
		op, val, ok := parseImpactFilter(opts.Impact)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return ok && compareImpact(EffectiveImpactOf(c, now), op, val)
		})
	}

	// The unadjusted twin, same grammar and same safe-degradation.
	if opts.RawImpact != "" {
		op, val, ok := parseImpactFilter(opts.RawImpact)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return ok && compareImpact(c.Impact, op, val)
		})
	}

	// The vulnerability numbers, through the SAME comparison parser — a second
	// grammar would be a second thing to learn and a second thing to get wrong.
	// A requirement carrying no such score matches no comparison on it, rather
	// than defaulting to zero and matching "<5" for the wrong reason.
	if opts.Cvss != "" {
		op, val, ok := parseImpactFilter(opts.Cvss)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			score, present := cvssScoreOf(c)
			return ok && present && compareImpact(score, op, val)
		})
	}
	if opts.Epss != "" {
		op, val, ok := parseImpactFilter(opts.Epss)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return ok && c.Epss != nil && compareImpact(c.Epss.Score, op, val)
		})
	}
	if opts.Kev != "" {
		want, ok := parseKevFilter(opts.Kev)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return ok && inKev(c) == want
		})
	}
	if opts.Cwe.Active() {
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			carried := map[string]bool{}
			for _, raw := range c.Cwe {
				for _, id := range hdfutil.ExtractCWEIDs(raw) {
					carried[id] = true
				}
			}
			return opts.Cwe.Match(func(want string) bool {
				for _, id := range hdfutil.ExtractCWEIDs(want) {
					if carried[id] {
						return true
					}
				}
				return false
			})
		})
	}

	// CCI filter (OR across values)
	if opts.CCI.Active() {
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return opts.CCI.Match(func(want string) bool {
				return tagContains(c.Tags, "cci", strings.ToUpper(want))
			})
		})
	}

	// NIST filter (OR across values)
	if opts.NIST.Active() {
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return opts.NIST.Match(func(want string) bool {
				return tagMatchesGlob(c.Tags, "nist", want)
			})
		})
	}

	// ID filter (requirement ID / STIG ID / GID / group title)
	if opts.ID != "" {
		id := opts.ID
		// A wildcard opts into glob matching; without one this stays the exact,
		// case-sensitive lookup it has always been. That matters because the id a
		// user knows is often not the id the document carries — converters mint
		// prefixed ids (Grype/CVE-...), so a bare CVE matches nothing — while
		// `search` reaches title, description and code and therefore also matches a
		// CVE merely cross-referenced in another finding's prose. A glob reads only
		// the identifier, so it can be precise about which requirement it names.
		if strings.ContainsAny(id, "*?") {
			filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
				return tagMatchesGlob(c.Tags, "stig_id", id) ||
					tagMatchesGlob(c.Tags, "gid", id) ||
					tagMatchesGlob(c.Tags, "gtitle", id) ||
					matchesGlob(c.ID, id)
			})
		} else {
			filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
				return tagContains(c.Tags, "stig_id", id) ||
					tagContains(c.Tags, "gid", id) ||
					tagContains(c.Tags, "gtitle", id) ||
					c.ID == id
			})
		}
	}

	// Generic tag filter (OR across values)
	if opts.Tag.Active() {
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return opts.Tag.Match(func(want string) bool {
				// A colonless value names no key, so it matches nothing rather
				// than disappearing and letting the whole document through. The
				// CLI refuses one before it reaches here; this is the safe floor
				// for any caller that does not.
				key, value, found := strings.Cut(want, ":")
				return found && key != "" && tagMatchesGlob(c.Tags, key, value)
			})
		})
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

// ValidTag reports whether s is a tag expression at all. A value carrying no
// colon names no key, so it can never match — and unlike the label filter, which
// merely selected nothing, a colonless tag was DROPPED from the filter list
// entirely, so a predicate made only of colonless values matched the whole
// document. Refused rather than tolerated in either direction.
func ValidTag(s string) bool {
	key, _, found := strings.Cut(s, ":")
	return found && key != ""
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

// ValidBaselineLabel reports whether s is a label expression at all. A value
// carrying no colon names no key, so it can never match any document — the same
// forever-green gate a misspelled status value produces, which is why it is
// refused rather than allowed to select nothing.
func ValidBaselineLabel(s string) bool {
	key, _, found := strings.Cut(s, ":")
	return found && key != ""
}

// governingPoamType returns the KIND of the governing POA&M, or "" when the
// governing entry is an override or nothing governs. It resolves through the
// same index governingDisposition uses, so disposition and poamType can never
// name different entries — a requirement reporting disposition "poam" and one
// reporting a poamType are by construction the same requirement.
//
// Reading the GOVERNING plan rather than any carried plan is the whole point: a
// requirement carrying a lapsed remediation under a live mitigation is governed
// by the mitigation, and matching it on "remediation" would let a dead plan
// answer for a live one.
func governingPoamType(control hdf.EvaluatedRequirement, ref time.Time) string {
	entries := statusOverrideInputs(control.StatusOverrides)
	entries = append(entries, poamInputs(control.Poams)...)

	i := hdfutil.GoverningOverrideIndex(entries, func(int) bool { return true }, ref)
	if i < len(control.StatusOverrides) {
		return ""
	}
	return string(control.Poams[i-len(control.StatusOverrides)].Type)
}

// baselineLabelsMatch reports whether a baseline satisfies any of the "key:value"
// label predicates. No predicates means every baseline qualifies; otherwise one
// must match, so several values OR the way every other multi-value filter does.
//
// A predicate without a colon is refused at the boundary by ValidBaselineLabel
// rather than handled here, because selecting nothing and being ignored produce
// the SAME false green under a max bound: the gate passes while the caller
// believes a filter was applied. Reaching this function it selects nothing, which
// is the safe half of that pair.
func baselineLabelsMatch(labels map[string]string, predicates Values) bool {
	if !predicates.Active() {
		return true
	}
	return predicates.Match(func(p string) bool {
		key, value, found := strings.Cut(p, ":")
		return found && labelMatchesGlob(labels, key, value)
	})
}

// labelMatchesGlob reports whether a label KEY is present and its value matches
// the pattern. Deliberately not tagMatchesGlob: a tag value may be a list, which
// is why that one goes through TagStrings, while a label is exactly one string by
// schema (additionalProperties: {type: string}). An absent key matches nothing,
// including against "*" — the predicate asks about a label the baseline does not
// carry, and there is nothing to match.
func labelMatchesGlob(labels map[string]string, key, pattern string) bool {
	value, ok := labels[key]
	if !ok {
		return false
	}
	return safeGlobMatch(value, pattern)
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

// PoamTypeValues is the closed vocabulary the poamType filter accepts: the
// schema's POA&M type enum. It is deliberately NOT merged into DispositionValues
// — disposition answers which Override_Type governs, and a plan's kind is not an
// override type. Naming the generated constants pins their VALUES, not the
// membership, exactly as DispositionValues does; hdf-libs-g2suj is the assertion
// against the bundled schema enum that would close that for both.
var PoamTypeValues = []string{
	string(hdf.POAMTypeRemediation),
	string(hdf.Mitigation),
	string(hdf.RiskAcceptance),
	string(hdf.VendorDependency),
}

// ValidPoamType reports whether s names a POA&M kind. A value outside the
// vocabulary can only ever match nothing, so callers refuse it rather than
// letting it read as "asked and found none".
func ValidPoamType(s string) bool {
	return canonical(PoamTypeValues, nil, s) != ""
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
// requirement, or "" when none does: the most recently applied non-expired
// override, whatever it carries. That is the schema's own definition, and it is
// the rule hdf-diff has always used to compute the effective checksum.
//
// Eligibility is deliberately unfiltered here, unlike the status and impact
// ladders. Requiring a status — as this did — meant an override carrying only an
// impact governed nothing, so `--disposition riskAdjustment` could not match the
// shape a riskAdjustment normally has. The cost is that disposition may name a
// different override than the one that decided the status, which is what
// per-field eligibility means rather than a contradiction: disposition answers
// "what is the latest thing anyone did to this requirement", not "what set its
// status".
func governingDisposition(control hdf.EvaluatedRequirement, ref time.Time) string {
	// Overrides and POA&Ms are ONE ordered set, not two tiers: the schema defines
	// disposition as "the most recent non-expired override or POAM governing this
	// requirement". Both carry appliedAt and expiresAt with the same meaning, so
	// the existing resolver decides between them without inventing a comparison —
	// its input set widens rather than the rule changing.
	entries := statusOverrideInputs(control.StatusOverrides)
	entries = append(entries, poamInputs(control.Poams)...)

	i := hdfutil.GoverningOverrideIndex(entries, func(int) bool { return true }, ref)
	if i < 0 {
		return ""
	}
	if i < len(control.StatusOverrides) {
		return string(control.StatusOverrides[i].Type)
	}
	// A POA&M's own kind — remediation, mitigation, riskAcceptance,
	// vendorDependency — is not a member of Override_Type, which is what
	// disposition is typed as, so every governing POA&M reports the flat "poam".
	return string(hdf.Poam)
}

// poamInputs projects POA&Ms onto the same shape the override resolver compares,
// carrying no status or impact because a POA&M changes neither: it tracks the
// work being done about a failure rather than adjudicating it.
func poamInputs(poams []hdf.PoamElement) []hdfutil.StatusOverrideInput {
	inputs := make([]hdfutil.StatusOverrideInput, len(poams))
	for i, p := range poams {
		inputs[i] = hdfutil.StatusOverrideInput{AppliedAt: p.AppliedAt, ExpiresAt: p.ExpiresAt}
	}
	return inputs
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

// EffectiveImpactOf is the requirement's impact after its governing non-expired
// impact override, else its own. Computed here rather than injected like StatusOf
// because impact has no competing conventions to reconcile — the ladder in
// hdf-utilities is canonical — and because the caller already supplies the clock
// this needs. A zero ref means now.
func EffectiveImpactOf(control hdf.EvaluatedRequirement, ref time.Time) float64 {
	return hdfutil.ComputeEffectiveImpact(hdfutil.EffectiveStatusInput{
		Impact:    control.Impact,
		Overrides: statusOverrideInputs(control.StatusOverrides),
	}, ref)
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
		if o.Impact != nil {
			// Carried so effective IMPACT resolves from the same overrides;
			// eligibility is per-field, so one override may govern one and not
			// the other.
			value := o.Impact.Value
			inputs[i].Impact = &value
		}
	}
	return inputs
}

// cvssScoreOf is the requirement's authoritative CVSS score, and whether it has
// one at all.
//
// Two decisions live here. First, an entry's score is its computedScore when the
// producer supplied one, else its baseScore: the schema calls computedScore "the
// score consumers should treat as authoritative for risk decisions when
// present", and converters populate it: nessus-to-hdf writes a requirement-level
// computedScore when it has the metrics to recompute one, and hdf-to-csv already
// resolves computedScore-else-baseScore for its own column. A gate reading
// baseScore alone would disagree with both.
//
// Note this does NOT reach `hdf enrich --recompute-cvss`, which writes its
// recomputed score into a riskAdjustment OVERRIDE's cvss block rather than the
// requirement's own cvss[]. Reaching those is hdf-libs-5cim9's overrideCvss
// candidate, deliberately not in this card.
// Second, a requirement may carry one CVSS entry per CVE, and it resolves to the
// HIGHEST of them: a finding matching several CVEs is as dangerous as its worst.
func cvssScoreOf(control hdf.EvaluatedRequirement) (float64, bool) {
	best, found := 0.0, false
	for i := range control.Cvss {
		c := &control.Cvss[i]
		score, ok := 0.0, false
		switch {
		case c.ComputedScore != nil:
			score, ok = *c.ComputedScore, true
		case c.BaseScore != nil:
			score, ok = *c.BaseScore, true
		}
		if ok && (!found || score > best) {
			best, found = score, true
		}
	}
	return best, found
}

// inKev reports CISA Known Exploited Vulnerabilities membership. An absent kev
// block reads as false: a requirement nobody checked against the catalog is not
// known-exploited, and treating absence as unknown would leave "kev: false"
// unable to express "everything CISA does not list".
func inKev(control hdf.EvaluatedRequirement) bool {
	return control.Kev != nil && control.Kev.InKev
}

// parseKevFilter accepts only "true" and "false". Anything else is refused by
// ValidKevFilter before a document is read; here it matches nothing rather than
// silently meaning one of them.
func parseKevFilter(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// ValidKevFilter reports whether a kev filter value is one this engine
// understands, for callers to reject up front rather than matching nothing.
func ValidKevFilter(s string) bool {
	_, ok := parseKevFilter(s)
	return ok
}
