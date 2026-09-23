package hdfengine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ruleCases is the shared cross-language contract for threshold rules:
// test/compliance.test.ts reads the SAME file and runs the SAME cases, so the two
// evaluators cannot drift. The reference clock lives in the file, which keeps
// expiry a property of the fixture rather than of the day the suite runs.
type ruleCases struct {
	Now            string            `json:"now"`
	RefusalByCount map[string]string `json:"refusalByCount"`
	Fixture        hdf.HDFResults    `json:"fixture"`
	Cases          []struct {
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
			got := EvaluateRules(config, table.Fixture, RuleOptions{
				Now:      now,
				StatusOf: effectiveStatusOf(false),
			})
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

	assert.Contains(t, violations, "nothing fails without a plan: 1 matched, maximum 0",
		"the rule must be applied")
	assert.Contains(t, violations, "failed.total: 2 exceeds maximum 0",
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
