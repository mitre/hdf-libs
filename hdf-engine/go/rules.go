package hdfengine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ThresholdRule is a policy the pre-existing assertions cannot express: a filter
// predicate plus a bound on how many requirements may match it.
//
// "The grid" appears in comments here as local shorthand for what a threshold
// file could assert before rules: the compliance percentage, the per-status
// per-severity count bounds, and the `controls` lists that require a named
// control to land in a given bucket. It is OUR word, not SAF CLI's — SAF's docs
// describe thresholds functionally and name no shape — so it stays out of
// user-facing text. What rules add is selection by FIELD: `controls` names a
// requirement by id, and nothing before could say "requirements where x".
//
// Rules are additive; the pre-existing assertions remain the SAF-compatible
// floor, and all of them are assertions in one policy, so every one must hold.
// Two decisions, recorded because a policy author will otherwise assume one of
// them: a rule bounds a COUNT and not a percentage — the grid's compliance
// min/max remains the only percentage bound, and extending rules to percentages
// is deferred rather than excluded — and a rule evaluates over the WHOLE
// document, not per baseline. A policy that wants one baseline says so with the
// baseline predicate.
type ThresholdRule struct {
	// Name is optional and exists for the violation message. A rule without one
	// is identified by its predicate, which is the only other handle a reader
	// has.
	Name  string        `yaml:"name,omitempty" json:"name,omitempty"`
	Where RulePredicate `yaml:"where" json:"where"`
	Min   *int          `yaml:"min,omitempty" json:"min,omitempty"`
	Max   *int          `yaml:"max,omitempty" json:"max,omitempty"`
}

// RulePredicate is the vocabulary a rule may name. It is deliberately the filter
// engine's own vocabulary rather than a second one: a rule and an `hdf query`
// invocation then mean the same thing, so a gate can be prototyped with query and
// pasted into a spec. Values within a field OR; fields AND.
type RulePredicate struct {
	Status    Values `yaml:"status,omitempty" json:"status,omitempty"`
	Severity  Values `yaml:"severity,omitempty" json:"severity,omitempty"`
	Impact    string `yaml:"impact,omitempty" json:"impact,omitempty"`
	RawImpact string `yaml:"rawImpact,omitempty" json:"rawImpact,omitempty"`
	Cvss      string `yaml:"cvss,omitempty" json:"cvss,omitempty"`
	Epss      string `yaml:"epss,omitempty" json:"epss,omitempty"`
	Kev       string `yaml:"kev,omitempty" json:"kev,omitempty"`
	Cwe       Values `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	CCI       Values `yaml:"cci,omitempty" json:"cci,omitempty"`
	NIST      Values `yaml:"nist,omitempty" json:"nist,omitempty"`
	ID        string `yaml:"id,omitempty" json:"id,omitempty"`
	Tag       Values `yaml:"tag,omitempty" json:"tag,omitempty"`
	Search    string `yaml:"search,omitempty" json:"search,omitempty"`
	Baseline  string `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	// BaselineLabel selects by the labels of the baseline a requirement sits in,
	// which is what makes "nothing fails in anything labelled
	// environment=production" expressible as a policy rather than only as a query.
	BaselineLabel Values `yaml:"baselineLabel,omitempty" json:"baselineLabel,omitempty"`
	Disposition   Values `yaml:"disposition,omitempty" json:"disposition,omitempty"`
	// PoamType names the KIND of the governing POA&M, which disposition collapses
	// to the flat "poam" because it is typed Override_Type and a plan's kind is
	// not an override type.
	PoamType Values `yaml:"poamType,omitempty" json:"poamType,omitempty"`
	Poams    string `yaml:"poams,omitempty" json:"poams,omitempty"`
}

// RuleOptions carries what rule evaluation needs beyond the document: the
// reference clock for expiry, and the status resolver. StatusOf is injected
// rather than assumed so a rule and the grid's counts cannot disagree about what
// "failed" means on the same document.
type RuleOptions struct {
	Now      time.Time
	StatusOf func(control hdf.EvaluatedRequirement) string
}

// filterOptions maps a predicate onto the engine filter. Every field is a
// pass-through: the point of reusing the vocabulary is that there is nothing to
// translate, and a new filter field becomes a rule field by adding it here.
func (p RulePredicate) filterOptions(opts RuleOptions) Options {
	return Options{
		Status:        p.Status,
		Severity:      p.Severity,
		Impact:        p.Impact,
		RawImpact:     p.RawImpact,
		Cvss:          p.Cvss,
		Epss:          p.Epss,
		Kev:           p.Kev,
		Cwe:           p.Cwe,
		CCI:           p.CCI,
		NIST:          p.NIST,
		ID:            p.ID,
		Tag:           p.Tag,
		Search:        p.Search,
		Baseline:      p.Baseline,
		BaselineLabel: p.BaselineLabel,
		Disposition:   p.Disposition,
		PoamType:      p.PoamType,
		Poams:         p.Poams,
		Now:           opts.Now,
		// Inert while a rule sets no Limit — Filter only consults Count to decide
		// whether a Limit may stop the scan — but set anyway so a bound can never
		// be judged against a truncated population if one is ever introduced.
		Count:    true,
		StatusOf: opts.StatusOf,
	}
}

// describe renders a predicate for a violation message, fields sorted so the
// same rule always reads the same way. Values within a field join with "|",
// which is what they mean.
func (p RulePredicate) describe() string {
	var parts []string
	// A negated field renders as "not X|Y" so an unnamed rule's identity says
	// which way round its predicate ran — "disposition: waiver" and
	// "disposition: not waiver" select opposite populations and would otherwise
	// print identically.
	add := func(key string, values Values) {
		if len(values.In) > 0 {
			parts = append(parts, key+": "+strings.Join(values.In, "|"))
		}
		if len(values.Not) > 0 {
			parts = append(parts, key+": not "+strings.Join(values.Not, "|"))
		}
	}
	addOne := func(key, value string) {
		if value != "" {
			parts = append(parts, key+": "+value)
		}
	}
	add("status", p.Status)
	add("severity", p.Severity)
	add("cci", p.CCI)
	add("nist", p.NIST)
	add("tag", p.Tag)
	add("disposition", p.Disposition)
	addOne("impact", p.Impact)
	addOne("rawImpact", p.RawImpact)
	addOne("cvss", p.Cvss)
	addOne("epss", p.Epss)
	addOne("kev", p.Kev)
	add("cwe", p.Cwe)
	add("baselineLabel", p.BaselineLabel)
	add("poamType", p.PoamType)
	addOne("id", p.ID)
	addOne("search", p.Search)
	addOne("baseline", p.Baseline)
	addOne("poams", p.Poams)
	sort.Strings(parts)
	return "{" + strings.Join(parts, ", ") + "}"
}

// label is what a violation calls the rule: its name when the author gave one,
// otherwise its predicate.
func (r ThresholdRule) label() string {
	if r.Name != "" {
		return r.Name
	}
	return "rule " + r.Where.describe()
}

// EvaluateRules applies every rule to the document and returns one violation per
// breached bound. Evaluation is filter → count → compare, calling the engine's
// own filter rather than a second matcher: the duplication this repo flags as its
// most common defect is exactly what a private rule matcher would be.
// EvaluateRules is EvaluateRulesContext with a background context, kept for
// callers that have none; a caller with a live context should pass it so a
// cancelled run stops filtering instead of finishing every rule.
func EvaluateRules(config *ThresholdConfig, results hdf.HDFResults, opts RuleOptions) []Violation {
	return EvaluateRulesContext(context.Background(), config, results, opts)
}

func EvaluateRulesContext(ctx context.Context, config *ThresholdConfig, results hdf.HDFResults, opts RuleOptions) []Violation {
	if config == nil || len(config.Rules) == 0 {
		return nil
	}
	var violations []Violation
	for _, rule := range config.Rules {
		// The matches, not just their count: naming which requirements broke a
		// gate is the difference between a red check a reader can act on and one
		// that sends them to an artifact and a script. This filter already ran.
		matches := Filter(ctx, results, rule.Where.filterOptions(opts))
		matched := len(matches)
		if rule.Max != nil && matched > *rule.Max {
			violations = append(violations, Violation{
				Message:  fmt.Sprintf("%s: %d matched, maximum %d", rule.label(), matched, *rule.Max),
				Findings: matches,
			})
		}
		if rule.Min != nil && matched < *rule.Min {
			// A minimum is breached by what is ABSENT, so the matches are the
			// requirements that DID qualify — fewer than required. Naming them
			// still helps: it says what the gate found rather than what it wanted.
			violations = append(violations, Violation{
				Message:  fmt.Sprintf("%s: %d matched, minimum %d", rule.label(), matched, *rule.Min),
				Findings: matches,
			})
		}
	}
	return violations
}

// ruleRefusal is what a caller is told when a policy carries rules that the
// path it used cannot evaluate. It reaches end users, so it names the spec and
// what to do about it rather than an internal function.
func ruleRefusal(count int) string {
	noun := "rules"
	if count == 1 {
		noun = "rule"
	}
	return fmt.Sprintf("this spec declares %d %s, which this evaluation path cannot apply; "+
		"the tool must evaluate rules against the document, not against counts alone", count, noun)
}

// ThresholdInput is everything an evaluation needs. It is a struct rather than a
// parameter list because rules made the list long enough that a caller could
// transpose two arguments of the same type without the compiler noticing.
type ThresholdInput struct {
	Results    hdf.HDFResults
	Counts     *StatusCounts
	Compliance float64
	ControlMap []ControlIDMapping
	Now        time.Time
	StatusOf   func(control hdf.EvaluatedRequirement) string
}

// NewThresholdInput derives everything an evaluation needs from ONE resolver.
// Building the counts, the control listing and the rules' status from the same
// function is the difference between a gate that cannot disagree with itself and
// one that merely happens not to: the struct's fields are independently settable,
// so two call sites hand-assembling it is two chances to pair a grid counted one
// way with rules filtered another.
func NewThresholdInput(results hdf.HDFResults, statusOf func(hdf.EvaluatedRequirement) string) ThresholdInput {
	return NewThresholdInputAt(results, statusOf, time.Time{})
}

// NewThresholdInputAt builds the input as of now, so the grid's counts and
// the rules judge an override's expiry against the same instant. A zero now
// means the wall clock, as every ladder here reads it.
func NewThresholdInputAt(results hdf.HDFResults, statusOf func(hdf.EvaluatedRequirement) string, now time.Time) ThresholdInput {
	counts := CountControlsByStatusAt(results, statusOf, now)
	return ThresholdInput{
		Results:    results,
		Counts:     counts,
		Compliance: CalculateCompliance(counts),
		ControlMap: MapControlIDsByStatusAt(results, statusOf, now),
		StatusOf:   statusOf,
		Now:        now,
	}
}

// Evaluate applies a whole policy — the grid and the rules — and returns every
// violation. This is the entry point a surface should call: ValidateThresholds
// evaluates the grid alone and refuses a config carrying rules, so a caller
// cannot half-implement a policy without being told.
func Evaluate(config *ThresholdConfig, in ThresholdInput) []Violation {
	return EvaluateContext(context.Background(), config, in)
}

// EvaluateContext is Evaluate under a caller's context: the grid half is
// already computed in the input, the rules half filters under ctx, and a
// cancelled run returns what it had — the caller reads ctx.Err() to tell a
// partial result from a clean one, as the query and aggregate tools do.
func EvaluateContext(ctx context.Context, config *ThresholdConfig, in ThresholdInput) []Violation {
	violations := validateGrid(config, in.Counts, in.Compliance, in.ControlMap)
	return append(violations, EvaluateRulesContext(ctx, config, in.Results, RuleOptions{
		Now:      in.Now,
		StatusOf: in.StatusOf,
	})...)
}

// Violation is one breached bound together with the requirements that breached
// it. Findings is empty in two cases, for two different reasons: a compliance
// percentage is a property of the whole document, so it has no offending
// requirement to name; and a controls list already names its requirement in the
// message, so repeating it would say the same thing twice.
//
// Findings from a RULE are the filter's own matches and carry every field. Those
// from a COUNT bound are rebuilt from the control map, which holds only id,
// title, status and severity — so Impact, Baseline, BaselineIndex and Index are
// zero there rather than the requirement's real values. The CLI prints none of
// them; a consumer serializing Findings should not read them as data.
type Violation struct {
	Message  string
	Findings []Match
}

// String is the message alone, so a caller that only wants the verdict reads the
// same text it always did.
func (v Violation) String() string { return v.Message }

// ViolationMessages is the messages of a violation list, for a caller that wants
// the verdict without the findings.
func ViolationMessages(violations []Violation) []string {
	if len(violations) == 0 {
		return nil
	}
	messages := make([]string, 0, len(violations))
	for _, v := range violations {
		messages = append(messages, v.Message)
	}
	return messages
}
