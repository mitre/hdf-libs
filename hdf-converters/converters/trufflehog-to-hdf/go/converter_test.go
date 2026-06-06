package trufflehog

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

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "trufflehog-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertTrufflehogToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertTrufflehogToHDF_EmptyFindings(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "trufflehog-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "TruffleHog")
	assert.Contains(t, req.Results[0].CodeDesc, "scanned")
}

// ---- Minimal fixture: single object ----

func TestConvertTrufflehogToHDF_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// minimal.json is a single AWS finding → 1 requirement ("AWS PLAIN")
	assert.Len(t, result.Baselines[0].Requirements, 1)
	assert.Len(t, result.Baselines[0].Requirements[0].Results, 1)
}

func TestConvertTrufflehogToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "TruffleHog Scan", result.Baselines[0].Name)
}

func TestConvertTrufflehogToHDF_Impact(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	// All trufflehog findings are medium impact (0.5)
	assert.InDelta(t, 0.5, result.Baselines[0].Requirements[0].Impact, 0.001)
}

func TestConvertTrufflehogToHDF_Tags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.Equal(t, []string{"IA-5 (7)"}, nist)

	cci := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cci)
	assert.Contains(t, cci, "CCI-000202")
	assert.Contains(t, cci, "CCI-000203")
	assert.Contains(t, cci, "CCI-002367")
}

func TestConvertTrufflehogToHDF_Status(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all TruffleHog findings should be Failed (req %s)", req.ID)
		}
	}
}

func TestConvertTrufflehogToHDF_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	codeDesc := result.Baselines[0].Requirements[0].Results[0].CodeDesc
	assert.Contains(t, codeDesc, "new_key")
	assert.Contains(t, codeDesc, "0416560b")
	assert.Contains(t, codeDesc, "Git")
}

func TestConvertTrufflehogToHDF_Message(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	msg := result.Baselines[0].Requirements[0].Results[0].Message
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "Verified")
	assert.Contains(t, *msg, "Redacted")
}

func TestConvertTrufflehogToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Regexp(t, `^[a-f0-9]{64}$`, result.Baselines[0].ResultsChecksum.Value)
}

func TestConvertTrufflehogToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "hdf-converters", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Multi-detector fixture: JSON array ----

func TestConvertTrufflehogToHDF_MultiDetector(t *testing.T) {
	input := loadFixture(t, "input/multi-detector.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// 3 findings: 2 AWS PLAIN + 1 URI PLAIN → 2 requirements
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestConvertTrufflehogToHDF_Grouping(t *testing.T) {
	input := loadFixture(t, "input/multi-detector.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	aws := findRequirement(reqs, "AWS PLAIN")
	require.NotNil(t, aws, "expected requirement 'AWS PLAIN'")
	assert.Len(t, aws.Results, 2, "AWS PLAIN should have 2 results")

	uri := findRequirement(reqs, "URI PLAIN")
	require.NotNil(t, uri, "expected requirement 'URI PLAIN'")
	assert.Len(t, uri.Results, 1, "URI PLAIN should have 1 result")
}

func TestConvertTrufflehogToHDF_Target(t *testing.T) {
	input := loadFixture(t, "input/multi-detector.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "https://github.com/trufflesecurity/test_keys", result.Components[0].Name)
	assert.Equal(t, hdf.Repository, result.Components[0].Type)
}

func TestConvertTrufflehogToHDF_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/multi-detector.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "trufflehog")
}

// ---- NDJSON fixture ----

func TestConvertTrufflehogToHDF_NDJSON(t *testing.T) {
	input := loadFixture(t, "input/ndjson-input.ndjson")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// 3 lines: 1 URI PLAIN + 2 Postgres PLAIN → 2 requirements
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestConvertTrufflehogToHDF_VerificationError(t *testing.T) {
	input := loadFixture(t, "input/ndjson-input.ndjson")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	// All NDJSON findings have VerificationError set
	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		for _, r := range req.Results {
			require.NotNil(t, r.Message, "Message should not be nil")
			assert.Contains(t, *r.Message, "VerificationError")
		}
	}
}

func TestConvertTrufflehogToHDF_NDJSONDescription(t *testing.T) {
	input := loadFixture(t, "input/ndjson-input.ndjson")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	// Postgres findings have DetectorDescription
	reqs := result.Baselines[0].Requirements
	postgres := findRequirement(reqs, "Postgres PLAIN")
	require.NotNil(t, postgres)
	require.NotEmpty(t, postgres.Descriptions)
	assert.Equal(t, "default", postgres.Descriptions[0].Label)
	assert.Contains(t, postgres.Descriptions[0].Data, "Postgres")
}

// ---- Tool ----

func TestConvertTrufflehogToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "TruffleHog", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "JSON", *result.Tool.Format)
}

// ---- No target for filesystem sources ----

func TestConvertTrufflehogToHDF_NoTargetForFilesystem(t *testing.T) {
	input := loadFixture(t, "input/ndjson-input.ndjson")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	// NDJSON fixture only has Filesystem sources (no Git repository URL)
	assert.Empty(t, result.Components, "filesystem sources should not produce a target")
}

// ---- Requirement ID format ----

func TestConvertTrufflehogToHDF_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	// Single AWS PLAIN finding → ID should be "AWS PLAIN"
	assert.Equal(t, "AWS PLAIN", result.Baselines[0].Requirements[0].ID)
}

// ---- Requirement title ----

func TestConvertTrufflehogToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.NotNil(t, req.Title)
	assert.Equal(t, "Found AWS secret using PLAIN decoder", *req.Title)
}

// ---- Round-trip: output is valid JSON ----

func TestConvertTrufflehogToHDF_OutputIsValidJSON(t *testing.T) {
	input := loadFixture(t, "input/multi-detector.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)

	output, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(output, &parsed))
}

func TestConvertTrufflehogToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/multi-detector.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "trufflehog-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertTrufflehogToHDF(input, "0.1.0")
	})
}

func TestConvertTrufflehogToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertTrufflehogToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}
