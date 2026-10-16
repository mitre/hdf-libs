package grype_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countRequirements(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertGrypeToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

// One requirement per DISTINCT vulnerability id after roll-up, or one
// no-findings requirement when both arrays are empty. The finding count moved
// to ExpectedResultCount below.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		produced, convErr := countRequirements(t, data)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct grype vulnerability ids", unit)
		require.Equal(t, produced, expected, "relation broken for %s", filepath.Base(path))
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("{}"), []byte("garbage"), []byte("[]"), []byte("{\"matches\":[],\"ignoredMatches\":[]}")} {
		produced, convErr := countRequirements(t, bad)
		expected, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
		if convErr == nil {
			require.Equal(t, produced, expected, "input %q: relation broken", string(bad))
		}
	}
}

func countResults(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertGrypeToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range result.Baselines {
		for _, r := range b.Requirements {
			n += len(r.Results)
		}
	}
	return n, nil
}

// The result relation is what roll-up makes load-bearing: one result per match
// and per ignored match, whatever the requirement count collapses to. ADR-0017
// §6 makes this anchor mandatory for a rolled-up converter, because the
// requirement count no longer tracks the findings.
func TestExpectedResultCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		produced, convErr := countResults(t, data)
		expected, unit, expErr := ExpectedResultCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "grype matches and ignored matches", unit)
		require.Equal(t, produced, expected, "result relation broken for %s", filepath.Base(path))
	}
}

// §6 forbids de-duplicating results, which is only safe if no two results under
// one requirement were identical to begin with: a roll-up that produced twins
// would mean the grouping key had swallowed a distinction the source made. The
// card's decision point requires this guard per converter rather than relying
// on a one-time measurement.
func TestRollUpNeverProducesIdenticalResults(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		out, convErr := ConvertGrypeToHDF(data, testConverterVersion)
		if convErr != nil {
			continue
		}
		for _, b := range out.Baselines {
			for _, r := range b.Requirements {
				seen := make(map[string]bool, len(r.Results))
				for i, res := range r.Results {
					key, err := json.Marshal(res)
					require.NoError(t, err)
					require.False(t, seen[string(key)],
						"%s: requirement %q result %d is byte-identical to an earlier one",
						filepath.Base(path), r.ID, i)
					seen[string(key)] = true
				}
			}
		}
	}
}

// Roll-up collapses requirements but must never collapse results: wherever a
// fixture has a duplicated id the result count strictly exceeds the requirement
// count, and the surplus is exactly the number of entries that merged.
func TestRollUpMovesFindingsWithoutDroppingThem(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		reqs, convErr := countRequirements(t, data)
		if convErr != nil {
			continue
		}
		res, _ := countResults(t, data)
		require.GreaterOrEqual(t, res, reqs,
			"%s: results must never be fewer than requirements", filepath.Base(path))

		// The surplus is the number of findings that merged away, so the
		// requirement count plus the merge surplus must reconstruct the
		// findings exactly. A roll-up that dropped a finding breaks this even
		// though the inequality above still holds.
		expectedResults, _, err := ExpectedResultCount(data)
		require.NoError(t, err)
		expectedReqs, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, expectedResults, res, "%s: findings lost", filepath.Base(path))
		require.Equal(t, expectedReqs, reqs, "%s: requirement count drifted", filepath.Base(path))
		if expectedResults > expectedReqs {
			require.Greater(t, res, reqs,
				"%s: input has duplicate ids, so results must strictly exceed requirements",
				filepath.Base(path))
		}
	}
}
