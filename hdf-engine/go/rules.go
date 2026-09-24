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
	Status      []string `yaml:"status,omitempty" json:"status,omitempty"`
	Severity    []string `yaml:"severity,omitempty" json:"severity,omitempty"`
	Impact      string   `yaml:"impact,omitempty" json:"impact,omitempty"`
	CCI         []string `yaml:"cci,omitempty" json:"cci,omitempty"`
	NIST        []string `yaml:"nist,omitempty" json:"nist,omitempty"`
	ID          string   `yaml:"id,omitempty" json:"id,omitempty"`
	Tag         []string `yaml:"tag,omitempty" json:"tag,omitempty"`
	Search      string   `yaml:"search,omitempty" json:"search,omitempty"`
	Baseline    string   `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	Disposition []string `yaml:"disposition,omitempty" json:"disposition,omitempty"`
	Poams       string   `yaml:"poams,omitempty" json:"poams,omitempty"`
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
		Status:      p.Status,
		Severity:    p.Severity,
		Impact:      p.Impact,
		CCI:         p.CCI,
		NIST:        p.NIST,
		ID:          p.ID,
		Tag:         p.Tag,
		Search:      p.Search,
		Baseline:    p.Baseline,
		Disposition: p.Disposition,
		Poams:       p.Poams,
		Now:         opts.Now,
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
	add := func(key string, values []string) {
		if len(values) > 0 {
			parts = append(parts, key+": "+strings.Join(values, "|"))
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
func EvaluateRules(config *ThresholdConfig, results hdf.HDFResults, opts RuleOptions) []string {
	if config == nil || len(config.Rules) == 0 {
		return nil
	}
	var violations []string
	for _, rule := range config.Rules {
		matched := len(Filter(context.Background(), results, rule.Where.filterOptions(opts)))
		if rule.Max != nil && matched > *rule.Max {
			violations = append(violations, fmt.Sprintf("%s: %d matched, maximum %d", rule.label(), matched, *rule.Max))
		}
		if rule.Min != nil && matched < *rule.Min {
			violations = append(violations, fmt.Sprintf("%s: %d matched, minimum %d", rule.label(), matched, *rule.Min))
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
	counts := CountControlsByStatus(results, statusOf)
	return ThresholdInput{
		Results:    results,
		Counts:     counts,
		Compliance: CalculateCompliance(counts),
		ControlMap: MapControlIDsByStatus(results, statusOf),
		StatusOf:   statusOf,
	}
}

// Evaluate applies a whole policy — the grid and the rules — and returns every
// violation. This is the entry point a surface should call: ValidateThresholds
// evaluates the grid alone and refuses a config carrying rules, so a caller
// cannot half-implement a policy without being told.
func Evaluate(config *ThresholdConfig, in ThresholdInput) []string {
	violations := validateGrid(config, in.Counts, in.Compliance, in.ControlMap)
	return append(violations, EvaluateRules(config, in.Results, RuleOptions{
		Now:      in.Now,
		StatusOf: in.StatusOf,
	})...)
}
