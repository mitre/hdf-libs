package hdfengine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ruleCases is the shared cross-language contract for threshold rules:
// test/compliance.test.ts reads the SAME file and runs the SAME cases, so the two
// evaluators cannot drift. The reference clock lives in the file, which keeps
// expiry a property of the fixture rather than of the day the suite runs.
type ruleCases struct {
	Now             string            `json:"now"`
	PredicateFields []string          `json:"predicateFields"`
	RefusalByCount  map[string]string `json:"refusalByCount"`
	Fixture         hdf.HDFResults    `json:"fixture"`
	Cases           []struct {
		Name   string          `json:"name"`
		Rules  []ThresholdRule `json:"rules"`
		Expect []string        `json:"expect"`
	} `json:"cases"`
}

func loadRuleCases(t *testing.T) ruleCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "threshold-rule-cases.json"))
	require.NoError(t, err)
	var table ruleCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table
}

// A rule is a predicate plus a bound, evaluated by filtering the document and
// counting the matches — calling the engine's own filter rather than growing a
// second matcher beside it. Rules key on EFFECTIVE status, so amendments are
// already applied by the time a rule sees the document.
func TestEvaluateRules(t *testing.T) {
	table := loadRuleCases(t)
	now, err := time.Parse(time.RFC3339, table.Now)
	require.NoError(t, err)

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			config := &ThresholdConfig{Rules: tc.Rules}
			got := ViolationMessages(EvaluateRules(config, table.Fixture, RuleOptions{
				Now:      now,
				StatusOf: effectiveStatusOf(false),
			}))
			if len(tc.Expect) == 0 {
				assert.Empty(t, got, "a satisfied rule reports nothing")
				return
			}
			assert.Equal(t, tc.Expect, got)
		})
	}
}

// Rules and the legacy grid are both bounds in one policy: every one must hold,
// and a violation from either reads the same way. Evaluate is the entry point
// that applies both, so a surface cannot accidentally apply half a policy.
func TestEvaluateAppliesTheGridAndTheRules(t *testing.T) {
	table := loadRuleCases(t)
	now, err := time.Parse(time.RFC3339, table.Now)
	require.NoError(t, err)

	zero := 0
	statusOf := effectiveStatusOf(false)
	config := &ThresholdConfig{
		Failed: &ThresholdSeverity{Total: &ThresholdBound{Max: &zero}},
		Rules: []ThresholdRule{{
			Name:  "nothing fails without a plan",
			Where: RulePredicate{Status: []string{"failed"}, Poams: "none-valid"},
			Max:   &zero,
		}},
	}

	counts := CountControlsByStatus(table.Fixture, statusOf)
	violations := Evaluate(config, ThresholdInput{
		Results:    table.Fixture,
		Counts:     counts,
		Compliance: CalculateCompliance(counts),
		ControlMap: MapControlIDsByStatus(table.Fixture, statusOf),
		Now:        now,
		StatusOf:   statusOf,
	})

	messages := ViolationMessages(violations)
	assert.Contains(t, messages, "nothing fails without a plan: 1 matched, maximum 0",
		"the rule must be applied")
	assert.Contains(t, messages, "failed.total: 2 exceeds maximum 0",
		"and the grid's own bound must still be reported alongside it")
}

// The refusal is user-facing text emitted by both languages, so its wording lives
// in the shared table rather than in two hand-written copies — which is how the
// Go and TypeScript versions had already drifted apart in both text and position.
func TestRuleRefusalMatchesTheSharedTable(t *testing.T) {
	table := loadRuleCases(t)
	require.NotEmpty(t, table.RefusalByCount, "an empty table would pass vacuously")
	for count, want := range table.RefusalByCount {
		n, err := strconv.Atoi(count)
		require.NoError(t, err)
		assert.Equal(t, want, ruleRefusal(n), "refusal wording for %d", n)
	}
}

// Go maps predicate fields onto the filter explicitly while TypeScript spreads
// the object, so a field added to one language reaches the filter there and
// silently does nothing in the other. Both definitions are pinned to one list.
func TestRulePredicateFieldsMatchTheSharedTable(t *testing.T) {
	table := loadRuleCases(t)
	require.NotEmpty(t, table.PredicateFields, "an empty list would pass vacuously")

	var got []string
	rt := reflect.TypeOf(RulePredicate{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
			got = append(got, name)
		}
	}
	assert.ElementsMatch(t, table.PredicateFields, got,
		"a predicate field added here must be added to the shared table and to the TypeScript twin")
}

// A config carrying rules must never be evaluated as though it had none. Silently
// skipping them would report a passing gate over policy nobody applied — the
// false green this whole epic exists to eliminate, reached through a caller that
// has not been taught about rules yet.
func TestValidateThresholdsRefusesToSilentlySkipRules(t *testing.T) {
	zero := 0
	config := &ThresholdConfig{Rules: []ThresholdRule{{
		Name:  "nothing fails without a plan",
		Where: RulePredicate{Status: []string{"failed"}},
		Max:   &zero,
	}}}

	zeroBound := 0
	config.Failed = &ThresholdSeverity{Total: &ThresholdBound{Max: &zeroBound}}
	counts := &StatusCounts{Failed: SeverityCounts{Total: 1}}

	violations := ValidateThresholds(config, counts, 100, nil)
	require.Len(t, violations, 2, "the grid's own violation and the refusal")
	assert.Equal(t, "failed.total: 1 exceeds maximum 0", violations[0],
		"the refusal is appended after the grid's findings, not prepended")
	assert.Equal(t, ruleRefusal(1), violations[1])
}

// Naming the fields is not enough: Go maps them onto the filter one line at a
// time, so a field can be declared in the struct, listed in the table and
// present in the TypeScript const while its mapping line is missing — declared
// everywhere and inert. This sets every field to a distinctive value and asserts
// each one reaches Options, which is the wiring the name lists cannot see.
func TestRulePredicateFieldsReachTheFilterOptions(t *testing.T) {
	where := RulePredicate{
		Status:        []string{"failed"},
		Severity:      []string{"critical"},
		Impact:        ">=0.7",
		RawImpact:     ">=0.9",
		Cvss:          ">=7",
		Epss:          ">=0.5",
		Kev:           "true",
		Cwe:           []string{"CWE-79"},
		CCI:           []string{"CCI-000366"},
		NIST:          []string{"AC-2"},
		ID:            "V-1",
		Tag:           []string{"k:v"},
		Search:        "password",
		Baseline:      "b",
		BaselineLabel: []string{"environment:production"},
		Disposition:   []string{"waiver"},
		Poams:         PoamNoneValid,
	}
	opts := where.filterOptions(RuleOptions{})

	predicate := reflect.ValueOf(where)
	options := reflect.ValueOf(opts)
	for i := 0; i < predicate.NumField(); i++ {
		name := predicate.Type().Field(i).Name
		t.Run(name, func(t *testing.T) {
			require.False(t, predicate.Field(i).IsZero(), "the test must set every field or it proves nothing")
			target := options.FieldByName(name)
			require.True(t, target.IsValid(), "Options has no field %q", name)
			assert.False(t, target.IsZero(),
				"%s is declared on the predicate but never mapped onto Options — declared and inert", name)
		})
	}
}

// A violation that names only a count sends the reader to an artifact and a
// script to find out which requirement broke the build. The matches are already
// computed — EvaluateRules called len(Filter(...)) and discarded the slice — so
// carrying them costs nothing but keeping what was thrown away.
func TestRuleViolationCarriesTheMatchingFindings(t *testing.T) {
	table := loadRuleCases(t)
	now, err := time.Parse(time.RFC3339, table.Now)
	require.NoError(t, err)

	zero := 0
	config := &ThresholdConfig{Rules: []ThresholdRule{{
		Name:  "no failures",
		Where: RulePredicate{Status: []string{"failed"}},
		Max:   &zero,
	}}}
	violations := EvaluateRules(config, table.Fixture, RuleOptions{Now: now, StatusOf: effectiveStatusOf(false)})
	require.Len(t, violations, 1)

	v := violations[0]
	assert.Contains(t, v.Message, "no failures", "the message is unchanged")
	require.NotEmpty(t, v.Findings, "the requirements that matched must be carried")
	for _, f := range v.Findings {
		assert.NotEmpty(t, f.ID, "a finding must be identifiable")
		assert.Equal(t, "failed", f.Status)
	}
	// Every match, not a sample: the caller decides whether to elide.
	matched := Filter(context.Background(), table.Fixture, Options{
		Status:   []string{"failed"},
		StatusOf: effectiveStatusOf(false),
	})
	assert.Len(t, v.Findings, len(matched))
}

// A count bound has no filter behind it, but the control map ValidateThresholds
// already receives names every requirement and its bucket — so the offenders are
// recoverable there too.
func TestCountBoundViolationCarriesTheFindingsInThatBucket(t *testing.T) {
	table := loadRuleCases(t)
	now, err := time.Parse(time.RFC3339, table.Now)
	require.NoError(t, err)

	zero := 0
	config := &ThresholdConfig{Failed: &ThresholdSeverity{Total: &ThresholdBound{Max: &zero}}}
	in := NewThresholdInput(table.Fixture, effectiveStatusOf(false))
	in.Now = now

	violations := Evaluate(config, in)
	require.Len(t, violations, 1)

	v := violations[0]
	assert.Contains(t, v.Message, "failed.total")
	require.NotEmpty(t, v.Findings, "a count bound must name what it counted")
	for _, f := range v.Findings {
		assert.Equal(t, "failed", f.Status, "only the bucket that was bounded")
	}

	// The invariant that makes the list trustworthy: a reader counting the lines
	// must get the number the message reported. NotEmpty alone would pass against
	// a list that named one of five.
	counts := CountControlsByStatus(table.Fixture, effectiveStatusOf(false))
	assert.Len(t, v.Findings, counts.Failed.Total,
		"exactly as many findings as the bound counted")
}

// A severity label narrows the bucket; only `total` is the whole status. Its own
// fixture, because the shared one's failed requirements are ALL critical — so
// bounding failed.critical there lists the whole status either way and the test
// cannot fail. The precondition asserts the discriminating fact directly.
func TestCountBoundFindingsAreNarrowedBySeverity(t *testing.T) {
	critical, high := hdf.SeverityCritical, hdf.SeverityHigh
	results := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{Requirements: []hdf.EvaluatedRequirement{
		{ID: "CRIT-1", Impact: 0.9, Severity: &critical, Results: []hdf.RequirementResult{{Status: hdf.Failed}}},
		{ID: "HIGH-1", Impact: 0.7, Severity: &high, Results: []hdf.RequirementResult{{Status: hdf.Failed}}},
	}}}}
	statusOf := func(hdf.EvaluatedRequirement) string { return string(hdf.Failed) }

	counts := CountControlsByStatus(results, statusOf)
	require.Less(t, counts.Failed.Critical, counts.Failed.Total,
		"precondition: the bounded severity must be a STRICT subset, or narrowing is unobservable")

	zero := 0
	config := &ThresholdConfig{Failed: &ThresholdSeverity{Critical: &ThresholdBound{Max: &zero}}}
	violations := Evaluate(config, NewThresholdInput(results, statusOf))
	require.Len(t, violations, 1)

	require.Len(t, violations[0].Findings, counts.Failed.Critical,
		"a severity label lists only that severity, not the whole status")
	assert.Equal(t, "CRIT-1", violations[0].Findings[0].ID)
}

// The card's motivating policy — "no failures in anything labelled
// environment=production" — is a RULE, not a query, so the predicate has to
// carry the key or the capability does not exist where it was asked for.
func TestRulePredicateSelectsByBaselineLabel(t *testing.T) {
	results := loadQueryFixtureForRules(t)
	zero := 0

	breached := &ThresholdConfig{Rules: []ThresholdRule{{
		Name:  "nothing fails in production",
		Where: RulePredicate{Status: []string{"failed"}, BaselineLabel: []string{"environment:production"}},
		Max:   &zero,
	}}}
	violations := EvaluateRules(breached, results, RuleOptions{StatusOf: schemaStatusForRules})
	require.Len(t, violations, 1, "the labelled baseline has a failure, so the bound is breached")
	require.NotEmpty(t, violations[0].Findings)
	assert.Equal(t, "SV-230221", violations[0].Findings[0].ID)

	// The positive case above survives a predicate that is ignored entirely, since
	// the fixture's only failure happens to sit in the labelled baseline. Bounding
	// the label alone is what shows the selection NARROWS: the unlabelled
	// baseline's requirements must be absent, and the match must be a strict
	// subset of the document.
	all := &ThresholdConfig{Rules: []ThresholdRule{{
		Name:  "nothing in production",
		Where: RulePredicate{BaselineLabel: []string{"environment:production"}},
		Max:   &zero,
	}}}
	narrowed := EvaluateRules(all, results, RuleOptions{StatusOf: schemaStatusForRules})
	require.Len(t, narrowed, 1)
	matchedIDs := make([]string, 0, len(narrowed[0].Findings))
	for _, f := range narrowed[0].Findings {
		matchedIDs = append(matchedIDs, f.ID)
	}
	assert.NotContains(t, matchedIDs, "SV-100001", "the unlabelled baseline must not be selected")
	assert.Less(t, len(matchedIDs), len(Filter(context.Background(), results, Options{StatusOf: schemaStatusForRules})),
		"a label that selects the whole document narrows nothing")

	// The same rule against a label nothing carries selects nothing and passes —
	// which is what makes the predicate load-bearing rather than ignored.
	quiet := &ThresholdConfig{Rules: []ThresholdRule{{
		Name:  "nothing fails in staging",
		Where: RulePredicate{Status: []string{"failed"}, BaselineLabel: []string{"environment:staging"}},
		Max:   &zero,
	}}}
	assert.Empty(t, EvaluateRules(quiet, results, RuleOptions{StatusOf: schemaStatusForRules}))
}

func loadQueryFixtureForRules(t *testing.T) hdf.HDFResults {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "query-fixture.json"))
	require.NoError(t, err)
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	return results
}

func schemaStatusForRules(req hdf.EvaluatedRequirement) string {
	statuses := make([]string, 0, len(req.Results))
	for _, r := range req.Results {
		statuses = append(statuses, string(r.Status))
	}
	return hdfutil.WorstStatus(statuses)
}
