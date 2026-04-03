package msftsecurescore

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
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

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "msft-secure-score-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertMsftSecureScoreToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertMsftSecureScore_MissingSecureScore(t *testing.T) {
	_, err := ConvertMsftSecureScoreToHDF([]byte(`{"profiles": {"value": []}}`), testVersion)
	assert.Error(t, err)
}

func TestConvertMsftSecureScore_MissingProfiles(t *testing.T) {
	_, err := ConvertMsftSecureScoreToHDF([]byte(`{"secureScore": {"value": []}}`), testVersion)
	assert.Error(t, err)
}

// ---- Minimal fixture: baseline structure ----

func TestConvertMsftSecureScore_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	// Minimal fixture has 1 secureScore entry → 1 baseline
	require.Len(t, result.Baselines, 1)
	// Minimal fixture has 3 controlScores
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertMsftSecureScore_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Microsoft Secure Score", result.Baselines[0].Name)
}

func TestConvertMsftSecureScore_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "12345678-1234-1234-1234-1234567890abcd")
}

func TestConvertMsftSecureScore_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertMsftSecureScore_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "msft-secure-score-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertMsftSecureScore_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Microsoft Secure Score", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "JSON", *result.Tool.Format)
}

// ---- Target ----

func TestConvertMsftSecureScore_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, hdf.CloudAccount, result.Components[0].Type)
	assert.Contains(t, result.Components[0].Name, "12345678-1234-1234-1234-1234567890abcd")
}

// ---- Requirement ID format ----

func TestConvertMsftSecureScore_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// IDs should be "controlCategory:controlName" format
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req, "expected requirement Apps:McasFirewallLogUpload")
}

// ---- Requirement title from profile ----

func TestConvertMsftSecureScore_RequirementTitleFromProfile(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload has a matching profile with title
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "Deploy a log collector")
}

func TestConvertMsftSecureScore_RequirementTitleFallback(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// spo_idle_session_timeout has no matching profile → fallback title
	req := findRequirement(reqs, "Apps:spo_idle_session_timeout")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "spo_idle_session_timeout")
}

// ---- Impact from profile maxScore ----

func TestConvertMsftSecureScore_ImpactFromMaxScore(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload has profile.maxScore=1 → impact = 1/10 = 0.1
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)
	assert.InDelta(t, 0.1, req.Impact, 0.001)

	// dlp_datalossprevention has profile.maxScore=5 → impact = 5/10 = 0.5
	req2 := findRequirement(reqs, "Data:dlp_datalossprevention")
	require.NotNil(t, req2)
	assert.InDelta(t, 0.5, req2.Impact, 0.001)
}

func TestConvertMsftSecureScore_ImpactFallback(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// spo_idle_session_timeout has no profile → default 0.5
	req := findRequirement(reqs, "Apps:spo_idle_session_timeout")
	require.NotNil(t, req)
	assert.InDelta(t, 0.5, req.Impact, 0.001)
}

// ---- Status mapping ----

func TestConvertMsftSecureScore_StatusPassed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// dlp_datalossprevention has scoreInPercentage=100 → Passed
	req := findRequirement(reqs, "Data:dlp_datalossprevention")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestConvertMsftSecureScore_StatusFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload has scoreInPercentage=0, score=0, profile.maxScore=1 → Failed
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

// ---- CodeDesc from implementationStatus ----

func TestConvertMsftSecureScore_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "Feature in place: false")
}

// ---- Default description (HTML stripped) ----

func TestConvertMsftSecureScore_Description(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "Log collectors")
}

// ---- Fix description from profile remediation ----

func TestConvertMsftSecureScore_FixDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)

	fix := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fix, "expected a 'fix' description")
	assert.NotEmpty(t, fix.Data)
}

// ---- NIST tags (static analysis defaults) ----

func TestConvertMsftSecureScore_NistTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)

	nist := shared.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

// ---- StartTime ----

func TestConvertMsftSecureScore_StartTime(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.NotNil(t, req.Results[0].StartTime, "result should have start_time from createdDateTime")
}

// ---- Full fixture smoke test ----

func TestConvertMsftSecureScore_FullFixture(t *testing.T) {
	input := loadFixture(t, "input/combined.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	// Full fixture has 1 secureScore entry with 68 controlScores
	require.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 68)

	// Each requirement should have exactly 1 result
	for _, req := range result.Baselines[0].Requirements {
		assert.Len(t, req.Results, 1, "requirement %s should have exactly 1 result", req.ID)
	}
}

// ---- Timestamp ----

func TestConvertMsftSecureScore_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	assert.NotNil(t, result.Timestamp)
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "msft-secure-score-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftSecureScoreToHDF(input, "0.1.0")
	})
}
