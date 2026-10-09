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
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
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
		Name           string            `json:"name"`
		Rules          []ThresholdRule   `json:"rules"`
		Expect         []string          `json:"expect"`
		ExpectFindings [][]expectFinding `json:"expectFindings"`
	} `json:"cases"`
	GridCases []struct {
		Name           string            `json:"name"`
		Config         ThresholdConfig   `json:"config"`
		Expect         []string          `json:"expect"`
		ExpectFindings [][]expectFinding `json:"expectFindings"`
	} `json:"gridCases"`
}

// expectFinding is the shared shape a violation's findings are pinned to. Title
// is carried deliberately rather than ids alone: it is the field that ended up
// unasserted in BOTH languages at once, which is what this section prevents.
type expectFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
}

// assertFindings compares one violation's findings against the shared table.
func assertFindings(t *testing.T, want []expectFinding, got []Match) {
	t.Helper()
	require.Len(t, got, len(want), "a violation must name exactly the requirements the table lists")
	for i, w := range want {
		assert.Equal(t, w.ID, got[i].ID)
		assert.Equal(t, w.Title, got[i].Title, "the title is promised by the docs and was once unasserted")
		assert.Equal(t, w.Status, got[i].Status)
		assert.Equal(t, w.Severity, got[i].Severity)
	}
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
			violations := EvaluateRules(config, table.Fixture, RuleOptions{
				Now:      now,
				StatusOf: effectiveStatusOf(false),
			})
			got := ViolationMessages(violations)
			if len(tc.Expect) == 0 {
				assert.Empty(t, got, "a satisfied rule reports nothing")
				return
			}
			assert.Equal(t, tc.Expect, got)

			// The findings half, pinned by the same table so it cannot diverge
			// between languages the way it already did once.
			require.Len(t, tc.ExpectFindings, len(tc.Expect),
				"the table must state findings for every expected violation")
			for i, want := range tc.ExpectFindings {
				assertFindings(t, want, violations[i].Findings)
			}
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
			Where: RulePredicate{Status: In("failed"), Poams: "none-valid"},
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
		Where: RulePredicate{Status: In("failed")},
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
		Status:        In("failed"),
		Severity:      In("critical"),
		Impact:        ">=0.7",
		RawImpact:     ">=0.9",
		Cvss:          ">=7",
		Epss:          ">=0.5",
		Kev:           "true",
		Cwe:           In("CWE-79"),
		CCI:           In("CCI-000366"),
		NIST:          In("AC-2"),
		ID:            "V-1",
		Tag:           In("k:v"),
		Search:        "password",
		Baseline:      "b",
		BaselineLabel: In("environment:production"),
		Disposition:   In("waiver"),
		PoamType:      In("remediation"),
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

// The grid's bounds resolve their offenders from the control map rather than
// from a filter, so they are pinned by their own section of the same table. The
// two that deliberately name NOTHING sit beside a count bound that names two, on
// the same fixture — so an empty expectation here is a real assertion.
func TestEvaluateGridFindings(t *testing.T) {
	table := loadRuleCases(t)
	now, err := time.Parse(time.RFC3339, table.Now)
	require.NoError(t, err)
	require.NotEmpty(t, table.GridCases, "an empty section would pass vacuously")

	statusOf := effectiveStatusOf(false)
	for _, tc := range table.GridCases {
		t.Run(tc.Name, func(t *testing.T) {
			cfg := tc.Config
			in := NewThresholdInput(table.Fixture, statusOf)
			in.Now = now
			violations := Evaluate(&cfg, in)
			got := ViolationMessages(violations)
			if len(tc.Expect) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.Expect, got)

			require.Len(t, tc.ExpectFindings, len(tc.Expect))
			for i, want := range tc.ExpectFindings {
				assertFindings(t, want, violations[i].Findings)
			}
		})
	}
}

// NOTE: the two tests that used to sit here — TestRuleViolationCarriesTheMatchingFindings
// and TestCountBoundViolationCarriesTheFindingsInThatBucket — were deleted when
// the shared case table gained expectFindings/gridCases. They asserted COUNTS
// (findings length equals the filter's, or the bound's); the table pins exact
// membership by id, title, status and severity, which is strictly stronger and
// is read by both languages. Keeping both would have left two sources of truth,
// which is the defect this card exists to remove.

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
		Where: RulePredicate{Status: In("failed"), BaselineLabel: In("environment:production")},
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
		Where: RulePredicate{BaselineLabel: In("environment:production")},
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
		Where: RulePredicate{Status: In("failed"), BaselineLabel: In("environment:staging")},
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

// A caller with a live context gets to stop a rule evaluation; the background
// context the old entry point fabricated never could. Pre-cancelled, the filter
// yields nothing, and the caller tells a partial result from a clean one through
// ctx.Err() — the contract the query and aggregate tools already use.
func TestEvaluateRulesContext_StopsWhenCancelled(t *testing.T) {
	results := testhdf.Results(testhdf.Req("V-1", testhdf.Impact(0.9), testhdf.Status(hdf.Failed)))
	limit := 0
	config := &ThresholdConfig{Rules: []ThresholdRule{{Name: "no failures", Where: RulePredicate{Status: In("failed")}, Max: &limit}}}
	require.NotEmpty(t, EvaluateRulesContext(context.Background(), config, results, RuleOptions{StatusOf: effectiveStatusOf(false)}), "the rule trips on a live run")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Empty(t, EvaluateRulesContext(ctx, config, results, RuleOptions{StatusOf: effectiveStatusOf(false)}), "a cancelled run stops filtering rather than finishing every rule")
	assert.Error(t, ctx.Err(), "and the caller can see why it is empty")
}

// Now governs the grid half as well as the rules half: an impact override that
// has expired by now no longer re-scores the requirement the counts band it in.
func TestNewThresholdInputAt_JudgesOverrideExpiryAtNow(t *testing.T) {
	req := testhdf.Req("V-1", testhdf.Impact(0.9), testhdf.Status(hdf.Failed))
	req.StatusOverrides = []hdf.StatusOverride{{
		Type: hdf.RiskAdjustment, Reason: "compensated", AppliedBy: hdf.Identity{Type: hdf.Email, Identifier: "a@example.gov"},
		AppliedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		Impact: &hdf.ImpactOverride{Value: 0.1},
	}}
	results := testhdf.Results(req)
	statusOf := func(hdf.EvaluatedRequirement) string { return "failed" }

	before := NewThresholdInputAt(results, statusOf, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, 1, before.Counts.Failed.Low, "while the re-score governs, the failure counts as low")
	after := NewThresholdInputAt(results, statusOf, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, 1, after.Counts.Failed.Critical, "once it has expired, the raw 0.9 counts as critical")
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), after.Now, "and the rules half is handed the same instant")
}
