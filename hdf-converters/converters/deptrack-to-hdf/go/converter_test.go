package deptrack

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
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
		ConverterName:  "deptrack-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertDeptrackToHDF(input, testVersion) },
		MinimalFixture: "fpf-default.json",
	})
}

// ---- Default fixture: baseline structure ----

func TestConvertDeptrack_Default(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// fpf-default.json has 2 findings with unique matrix IDs
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestConvertDeptrack_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Dependency-Track Scan", result.Baselines[0].Name)
}

func TestConvertDeptrack_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "Acme Example")
}

func TestConvertDeptrack_Checksum(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertDeptrack_Generator(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "deptrack-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertDeptrack_Tool(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Dependency-Track", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "JSON", *result.Tool.Format)
}

// ---- Target ----

func TestConvertDeptrack_Target(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "Acme Example", result.Components[0].Name)
	assert.Equal(t, hdf.CopyrightApplication, result.Components[0].Type)
}

// ---- Severity → Impact mapping ----

func TestConvertDeptrack_SeverityLow(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// Both findings in fpf-default.json are LOW severity
	for _, req := range reqs {
		assert.InDelta(t, 0.3, req.Impact, 0.001)
	}
}

func TestConvertDeptrack_SeverityInfo(t *testing.T) {
	input := loadFixture(t, "input/fpf-info-vulnerability.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	// INFO severity → impact 0.0
	assert.InDelta(t, 0.0, reqs[0].Impact, 0.001)
}

// ---- CWE → NIST mapping ----

func TestConvertDeptrack_CweToNist(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// CWE-400 should have a NIST mapping
	nist := hdfutil.SafeStringSlice(reqs[0].Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

// ---- Requirement ID uses matrix field ----

func TestConvertDeptrack_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")
	require.NotNil(t, req, "expected requirement with matrix ID")
}

// ---- Requirement title includes purl and vuln title ----

func TestConvertDeptrack_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "pkg:npm/timespan@2.3.0")
	assert.Contains(t, *req.Title, "Regular Expression Denial of Service")
}

// ---- Descriptions: check and fix ----

func TestConvertDeptrack_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")
	require.NotNil(t, req)

	checkDesc := findDescription(req.Descriptions, "check")
	require.NotNil(t, checkDesc, "expected a 'check' description")
	assert.Contains(t, checkDesc.Data, "timespan")

	fixDesc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fixDesc, "expected a 'fix' description")
	assert.Contains(t, fixDesc.Data, "No direct patch")

	defaultDesc := findDescription(req.Descriptions, "default")
	require.NotNil(t, defaultDesc, "expected a 'default' description")
}

// ---- Status: all results are Failed ----

func TestConvertDeptrack_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all findings should be Failed (req %s)", req.ID)
		}
	}
}

// ---- Tags include CWE info ----

func TestConvertDeptrack_Tags(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	req := reqs[0]

	// nist
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist should be present")
	assert.NotEmpty(t, nist)

	// cci
	cci := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cci, "cci should be present")
	assert.NotEmpty(t, cci)

	// cweIds
	_, hasCweIds := req.Tags["cweIds"]
	assert.True(t, hasCweIds, "cweIds should be present")
}

// ---- No vulnerabilities fixture ----

func TestConvertDeptrack_NoVulnerabilities(t *testing.T) {
	input := loadFixture(t, "input/fpf-no-vulnerabilities.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 0)
	assert.Equal(t, "laravel", result.Components[0].Name)
}

// ---- Timestamp ----

func TestConvertDeptrack_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
}

// ---- Result codeDesc includes recommendation ----

func TestConvertDeptrack_ResultCodeDesc(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)

	assert.Contains(t, req.Results[0].CodeDesc, "Update to version 2.6.0 or later.")
}

// ---- Impact mapping table test ----

func TestGetImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"CRITICAL", 0.9},
		{"critical", 0.9},
		{"HIGH", 0.7},
		{"high", 0.7},
		{"MEDIUM", 0.5},
		{"medium", 0.5},
		{"LOW", 0.3},
		{"low", 0.3},
		{"INFO", 0.0},
		{"info", 0.0},
		{"UNASSIGNED", 0.5},
		{"unassigned", 0.5},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "deptrack-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertDeptrackToHDF(input, "0.1.0")
	})
}
