package conveyor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findBaseline(baselines []hdf.EvaluatedBaseline, titleContains string) *hdf.EvaluatedBaseline {
	for i := range baselines {
		if baselines[i].Title != nil && contains(*baselines[i].Title, titleContains) {
			return &baselines[i]
		}
	}
	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsStr(s, substr)))
}

func containsStr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "conveyor-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertConveyorToHDF(input, testVersion) },
		MinimalFixture: "sample-results.json",
	})
}

func TestConvertConveyor_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Baselines)
	var sawDerivation bool
	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			if req.ControlType != nil {
				sawDerivation = true
				switch *req.ControlType {
				case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
				default:
					t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
				}
			}
		}
	}
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

func TestConvertConveyor_MissingApiResponse(t *testing.T) {
	_, err := ConvertConveyorToHDF([]byte(`{"api_error_message": ""}`), testVersion)
	assert.Error(t, err)
}

// ---- Multi-baseline output (grouped by scanner) ----

func TestConvertConveyor_MultipleBaselines(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	// Fixture has 4 scanner types: Clamav, CodeQuality, Stigma, Moldy
	assert.GreaterOrEqual(t, len(result.Baselines), 4,
		"should produce at least one baseline per scanner type")
}

func TestConvertConveyor_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		assert.Equal(t, "Conveyor Scan", baseline.Name,
			"all baselines should have name 'Conveyor Scan'")
	}
}

func TestConvertConveyor_BaselineTitleIncludesScanner(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	scannerFound := make(map[string]bool)
	for _, baseline := range result.Baselines {
		require.NotNil(t, baseline.Title, "baseline title should not be nil")
		scannerFound[*baseline.Title] = true
	}

	// Verify scanner names appear in titles
	foundClamav := false
	foundMoldy := false
	for title := range scannerFound {
		if containsStr(title, "Clamav") {
			foundClamav = true
		}
		if containsStr(title, "Moldy") {
			foundMoldy = true
		}
	}
	assert.True(t, foundClamav, "should have a baseline with 'Clamav' in title")
	assert.True(t, foundMoldy, "should have a baseline with 'Moldy' in title")
}

// ---- Checksum ----

func TestConvertConveyor_Checksum(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		require.NotNil(t, baseline.ResultsChecksum, "each baseline should have a checksum")
		assert.Equal(t, hdf.Sha256, baseline.ResultsChecksum.Algorithm)
		assert.NotEmpty(t, baseline.ResultsChecksum.Value)
	}
}

// ---- Generator ----

func TestConvertConveyor_Generator(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "conveyor-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertConveyor_Tool(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Conveyor", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Target ----

func TestConvertConveyor_Target(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

// ---- Score-to-impact mapping ----

func TestConvertConveyor_ScoreToImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	// Find the Moldy baseline which has score=1000 and score=0
	moldy := findBaseline(result.Baselines, "Moldy")
	require.NotNil(t, moldy, "should have a Moldy baseline")

	hasMax := false
	hasZero := false
	for _, req := range moldy.Requirements {
		if req.Impact == 1.0 {
			hasMax = true
		}
		if req.Impact == 0.0 {
			hasZero = true
		}
	}
	assert.True(t, hasMax, "score=1000 should map to impact=1.0")
	assert.True(t, hasZero, "score=0 should map to impact=0.0")
}

// ---- Status: score=0 is Passed, non-zero is Failed ----

func TestConvertConveyor_StatusMapping(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	// Moldy baseline has both pass and fail
	moldy := findBaseline(result.Baselines, "Moldy")
	require.NotNil(t, moldy)

	hasPassed := false
	hasFailed := false
	for _, req := range moldy.Requirements {
		for _, r := range req.Results {
			if r.Status == hdf.Passed {
				hasPassed = true
			}
			if r.Status == hdf.Failed {
				hasFailed = true
			}
		}
	}
	assert.True(t, hasPassed, "score=0 results should be Passed")
	assert.True(t, hasFailed, "score>0 results should be Failed")
}

// ---- Requirement ID is sha256 of analyzed file ----

func TestConvertConveyor_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			assert.NotEmpty(t, req.ID, "requirement ID should not be empty")
			// IDs should be sha256 hashes (64 hex chars)
			assert.Regexp(t, `^[a-f0-9]{64}$`, req.ID,
				"requirement ID should be a sha256 hash")
		}
	}
}

// ---- File tree → filename mapping (title) ----

func TestConvertConveyor_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	// Some requirements should have file names from the file tree
	hasTitle := false
	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			if req.Title != nil && *req.Title != "" {
				hasTitle = true
			}
		}
	}
	assert.True(t, hasTitle, "some requirements should have a title from file tree")
}

// ---- Default description ----

func TestConvertConveyor_Description(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			require.NotEmpty(t, req.Descriptions,
				"each requirement should have at least one description")
			found := false
			for _, d := range req.Descriptions {
				if d.Label == "default" {
					found = true
				}
			}
			assert.True(t, found, "each requirement should have a 'default' description")
		}
	}
}

// ---- NIST tags ----

func TestConvertConveyor_NISTTags(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			nist := hdfutil.SafeStringSlice(req.Tags["nist"])
			assert.NotEmpty(t, nist,
				"each requirement should have NIST tags (req %s)", req.ID)
		}
	}
}

// ---- Results have CodeDesc ----

func TestConvertConveyor_ResultCodeDesc(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			for _, r := range req.Results {
				assert.NotEmpty(t, r.CodeDesc,
					"each result should have a code_desc (req %s)", req.ID)
			}
		}
	}
}

// ---- Results have StartTime ----

func TestConvertConveyor_ResultStartTime(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			for _, r := range req.Results {
				assert.NotEmpty(t, r.StartTime,
					"each result should have a start_time (req %s)", req.ID)
			}
		}
	}
}

// ---- Timestamp ----

func TestConvertConveyor_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	assert.NotNil(t, result.Timestamp, "HDF result should have a timestamp")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "conveyor-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertConveyorToHDF(input, "1.0.0")
	})
}

func TestConvertConveyor_EmptyResultsSynthesizesPlaceholder(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1, "empty results should yield exactly one placeholder baseline")
	baseline := result.Baselines[0]
	require.Len(t, baseline.Requirements, 1, "placeholder baseline should have exactly one requirement")

	req := baseline.Requirements[0]
	assert.Equal(t, "conveyor-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)

	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "Conveyor")
	assert.Contains(t, codeDesc, "Inspection of file: submissions/empty.zip")
}

// countConveyorResults parses raw Conveyor JSON generically — deliberately NOT
// the converter's structs — and returns the number of entries in the
// api_response.results map. The converter emits one requirement per result
// (distributed across per-scanner baselines), so this map size is the ground
// truth. results is a JSON object keyed by result id, not an array, so
// CountJSONItemsUnderKey does not apply.
func countConveyorResults(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		APIResponse struct {
			Results map[string]json.RawMessage `json:"results"`
		} `json:"api_response"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse Conveyor for anchor count")
	return len(doc.APIResponse.Results)
}

// Ground-truth anchor: one requirement per api_response.results entry. Counted
// independently of the converter so a silent under-extraction fails even when Go
// and TS goldens agree.
func TestConvertConveyor_ResultsAnchor(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	shared.AssertRequirementCount(t, result, countConveyorResults(t, input),
		"sample-results.json: one requirement per api_response.results entry")
}

func TestConvertConveyor_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			require.NotNil(t, req.VerificationMethod, "every requirement must have verificationMethod set")
			assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
				"requirement %q should be marked automated", req.ID)
		}
	}
}
