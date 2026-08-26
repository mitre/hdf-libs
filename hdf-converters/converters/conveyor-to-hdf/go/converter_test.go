package conveyor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// findRequirement returns the requirement with the given ID from a baseline.
func findRequirement(baseline *hdf.EvaluatedBaseline, id string) *hdf.EvaluatedRequirement {
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == id {
			return &baseline.Requirements[i]
		}
	}
	return nil
}

// ---- Value-pinning: source-derived startTime, tool.version, and timestamp ----
// The shared snapshot masks the top-level timestamp, so these assertions pin the
// exact source-derived values (per the u6j3/timestamp audit) in both languages.

func TestConvertConveyor_PinnedStartTimeFromServiceStarted(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	clamav := findBaseline(result.Baselines, "Clamav")
	require.NotNil(t, clamav, "should have a Clamav baseline")

	req := findRequirement(clamav, "033ecf8f77772375c638c1874f881a2aa300aae7073c23280554edf007174602")
	require.NotNil(t, req, "Clamav baseline should contain the pinned requirement")
	require.NotEmpty(t, req.Results)

	// service_started = 2023-08-28T12:23:54.164548Z → trimmed-UTC millis.
	assert.Equal(t, "2023-08-28T12:23:54.164Z",
		req.Results[0].StartTime.UTC().Format(time.RFC3339Nano))
}

func TestConvertConveyor_PinnedRunTimeFromMilestones(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	clamav := findBaseline(result.Baselines, "Clamav")
	require.NotNil(t, clamav, "should have a Clamav baseline")

	req := findRequirement(clamav, "033ecf8f77772375c638c1874f881a2aa300aae7073c23280554edf007174602")
	require.NotNil(t, req, "Clamav baseline should contain the pinned requirement")
	require.NotEmpty(t, req.Results)

	// service_started .164, service_completed .179 (trimmed-UTC millis) → 0.015s.
	require.NotNil(t, req.Results[0].RunTime, "run_time should be computed from the milestones")
	assert.InDelta(t, 0.015, *req.Results[0].RunTime, 1e-9)
}

func TestConvertConveyor_PinnedTypedTags(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	clamav := findBaseline(result.Baselines, "Clamav")
	require.NotNil(t, clamav, "should have a Clamav baseline")

	req := findRequirement(clamav, "033ecf8f77772375c638c1874f881a2aa300aae7073c23280554edf007174602")
	require.NotNil(t, req, "Clamav baseline should contain the pinned requirement")

	// created/expiry_ts canonicalized to trimmed-UTC millis (per repo policy).
	assert.Equal(t, "2023-08-28T12:23:54.184Z", req.Tags["created"])
	assert.Equal(t, "TLP:C", req.Tags["classification"])
	assert.Equal(t, "2023-08-31T12:23:54.184Z", req.Tags["expiry_ts"])
	assert.Equal(t, float64(351), req.Tags["size"])
	assert.Equal(t, "document/stigma", req.Tags["type"])
}

func TestConvertConveyor_TypedTagsOmittedWhenNull(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	// The trailing Moldy result (…548634) has null size/type but real created.
	moldy := findBaseline(result.Baselines, "Moldy")
	require.NotNil(t, moldy)
	req := findRequirement(moldy, "60e5941e7c34e77decf4d079ae18b531d35326ae8bd26d1dbca7ce23de548634")
	require.NotNil(t, req)

	assert.Equal(t, "2023-08-28T12:38:41.769Z", req.Tags["created"])
	_, hasSize := req.Tags["size"]
	_, hasType := req.Tags["type"]
	assert.False(t, hasSize, "null size must be omitted, not emitted as null")
	assert.False(t, hasType, "null type must be omitted, not emitted as null")
}

func TestConvertConveyor_PinnedToolVersion(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Version, "tool.version should be populated from service_version")
	assert.Equal(t, "4.3.0.0", *result.Tool.Version)
}

func TestConvertConveyor_PinnedTimestampFromTimesCompleted(t *testing.T) {
	input := loadFixture(t, "input/sample-results.json")
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	// api_response.times.completed = 2023-08-28T12:25:24.834217Z → trimmed-UTC millis.
	assert.Equal(t, "2023-08-28T12:25:24.834Z",
		result.Timestamp.UTC().Format(time.RFC3339Nano))
}

func TestConvertConveyor_StartTimeFallbackWhenMilestonesAbsent(t *testing.T) {
	input := []byte(`{"api_response":{"results":{"r1":{"sha256":"abc","response":{"service_name":"Moldy"},"result":{"score":0,"sections":[]}}}}}`)
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	require.NotEmpty(t, result.Baselines[0].Requirements)
	require.NotEmpty(t, result.Baselines[0].Requirements[0].Results)

	res := result.Baselines[0].Requirements[0].Results[0]
	// Absent service_started → zero time sentinel (never omitted; startTime is required).
	assert.Equal(t, "0001-01-01T00:00:00Z", res.StartTime.UTC().Format(time.RFC3339Nano))
	// Absent milestones → run_time omitted (optional field).
	assert.Nil(t, res.RunTime, "run_time must be omitted when milestones are absent")
}

func TestConvertConveyor_TimestampFallbackWhenTimesAbsent(t *testing.T) {
	input := []byte(`{"api_response":{"results":{"r1":{"sha256":"abc","response":{"service_name":"Moldy"},"result":{"score":0,"sections":[]}}}}}`)
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.False(t, result.Timestamp.IsZero(), "absent times.completed falls back to now(), never the zero time")
	assert.True(t, result.Timestamp.After(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
		"fallback timestamp should be a recent wall-clock time")
}

func TestConvertConveyor_ToolVersionFallbackWhenAbsent(t *testing.T) {
	input := []byte(`{"api_response":{"results":{"r1":{"sha256":"abc","response":{"service_name":"Moldy"},"result":{"score":0,"sections":[]}}}}}`)
	result, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Nil(t, result.Tool.Version, "no service_version → tool.version omitted")
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

func TestAbsentScore_NotReviewed(t *testing.T) {
	// A result block with no score carries no verdict: notReviewed @ 0.0 with
	// the reason in the message — never a silent pass. A genuine score of 0
	// stays a clean pass, and a positive score stays failed at score/1000.
	input := []byte(`{
		"api_error_message": "",
		"api_response": {
			"file_tree": {
				"sha-absent": {"name": ["absent.bin"], "sha256": "sha-absent"},
				"sha-zero": {"name": ["zero.bin"], "sha256": "sha-zero"},
				"sha-scored": {"name": ["scored.bin"], "sha256": "sha-scored"}
			},
			"results": {
				"sha-absent.SvcA.v1.k1": {"sha256": "sha-absent", "response": {"service_name": "SvcA", "milestones": {}}, "result": {"sections": [{"title_text": "t", "body": null, "body_format": "TEXT", "classification": "TLP:C", "depth": 0}]}},
				"sha-zero.SvcA.v1.k2": {"sha256": "sha-zero", "response": {"service_name": "SvcA", "milestones": {}}, "result": {"score": 0, "sections": []}},
				"sha-scored.SvcA.v1.k3": {"sha256": "sha-scored", "response": {"service_name": "SvcA", "milestones": {}}, "result": {"score": 500, "sections": []}}
			},
			"times": {}
		}
	}`)
	res, err := ConvertConveyorToHDF(input, testVersion)
	require.NoError(t, err)

	var all []hdf.EvaluatedRequirement
	for _, b := range res.Baselines {
		all = append(all, b.Requirements...)
	}
	byID := func(id string) *hdf.EvaluatedRequirement {
		for i := range all {
			if all[i].ID == id {
				return &all[i]
			}
		}
		return nil
	}

	absent := byID("sha-absent")
	require.NotNil(t, absent)
	assert.Equal(t, hdf.NotReviewed, absent.Results[0].Status)
	assert.Equal(t, 0.0, absent.Impact)
	require.NotNil(t, absent.Results[0].Message)
	assert.Contains(t, *absent.Results[0].Message, "no score")

	zero := byID("sha-zero")
	require.NotNil(t, zero)
	assert.Equal(t, hdf.Passed, zero.Results[0].Status)
	assert.Equal(t, 0.0, zero.Impact)

	scored := byID("sha-scored")
	require.NotNil(t, scored)
	assert.Equal(t, hdf.Failed, scored.Results[0].Status)
	assert.Equal(t, 0.5, scored.Impact)
}
