package fortify

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func totalRequirements(result *hdf.HDFResults) int {
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n
}

// Every fixture, including the clean FVDL that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.fvdl"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertFortifyToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "Fortify vulnerability classes", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The WebGoat scan carries 8 Vulnerability instances under 5 Description
// classIDs: a count of vulnerabilities would be wrong, Descriptions is right.
// Pinning both numbers keeps a per-vulnerability relation from passing.
func TestExpectedRequirementCount_CountsDescriptionsNotVulnerabilities(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "fortify_webgoat_results.fvdl"))
	require.NoError(t, err)
	var fvdl FVDL
	require.NoError(t, xml.Unmarshal(data, &fvdl))
	require.Equal(t, 8, len(fvdl.Vulnerabilities.Vulnerability), "fixture drifted")
	require.Equal(t, 5, len(fvdl.Descriptions), "fixture drifted")

	expected, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	require.Equal(t, 5, expected)
	result, err := ConvertFortifyToHDF(data, "test")
	require.NoError(t, err)
	require.Equal(t, 5, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not xml"), []byte("<FVDL/>")} {
		_, convErr := ConvertFortifyToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
