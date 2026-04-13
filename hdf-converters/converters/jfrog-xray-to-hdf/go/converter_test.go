package jfrogxray

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
		ConverterName:  "jfrog-xray-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertJfrogXrayToHDF(input, testVersion) },
		MinimalFixture: "jfrog_xray_sample.json",
	})
}

// ---- Baseline structure ----

func TestConvertJfrogXray_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
}

func TestConvertJfrogXray_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Equal(t, "JFrog Xray Scan", result.Baselines[0].Name)
}

func TestConvertJfrogXray_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	// 30 entries with 17 unique summaries → 17 unique requirements
	assert.Len(t, result.Baselines[0].Requirements, 17)
}

func TestConvertJfrogXray_Checksum(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertJfrogXray_Generator(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "jfrog-xray-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertJfrogXray_Tool(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "JFrog Xray", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "JSON", *result.Tool.Format)
}

// ---- Target ----

func TestConvertJfrogXray_Target(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "JFrog Xray Scan", result.Components[0].Name)
	assert.Equal(t, hdf.CopyrightApplication, result.Components[0].Type)
}

// ---- Severity → Impact mapping ----

func TestConvertJfrogXray_SeverityImpact(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// All requirements should have valid impact values
	for _, req := range reqs {
		assert.GreaterOrEqual(t, req.Impact, 0.0)
		assert.LessOrEqual(t, req.Impact, 1.0)
	}

	// Check specific severity levels exist by looking for known impacts
	hasHigh := false
	hasMedium := false
	hasLow := false
	for _, req := range reqs {
		if req.Impact == 0.7 {
			hasHigh = true
		}
		if req.Impact == 0.5 {
			hasMedium = true
		}
		if req.Impact == 0.3 {
			hasLow = true
		}
	}
	assert.True(t, hasHigh, "expected High severity (0.7) requirements")
	assert.True(t, hasMedium, "expected Medium severity (0.5) requirements")
	assert.True(t, hasLow, "expected Low severity (0.3) requirements")
}

// ---- ID generation: empty ID → hash of summary ----

func TestConvertJfrogXray_EmptyIDGeneratesHash(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		assert.NotEmpty(t, req.ID, "all requirements should have a non-empty ID")
	}
}

// ---- Deduplication: duplicate summaries → grouped results ----

func TestConvertJfrogXray_Dedup(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// Total results across all requirements should equal total data entries (27)
	totalResults := 0
	for _, req := range reqs {
		totalResults += len(req.Results)
	}
	assert.Equal(t, 27, totalResults, "total results should match total data entries")

	// Some requirements should have more than 1 result (duplicate summaries)
	hasMultipleResults := false
	for _, req := range reqs {
		if len(req.Results) > 1 {
			hasMultipleResults = true
			break
		}
	}
	assert.True(t, hasMultipleResults, "expected deduplication to group entries by ID/summary")
}

// ---- All results are Failed ----

func TestConvertJfrogXray_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all JFrog Xray vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- Description ----

func TestConvertJfrogXray_Description(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// Every requirement should have at least a default description
	for _, req := range reqs {
		desc := findDescription(req.Descriptions, "default")
		require.NotNil(t, desc, "expected a 'default' description for requirement %s", req.ID)
		assert.NotEmpty(t, desc.Data)
	}
}

// ---- CodeDesc includes source_comp_id and version info ----

func TestConvertJfrogXray_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// Every result should have a non-empty code_desc
	for _, req := range reqs {
		for _, r := range req.Results {
			assert.NotEmpty(t, r.CodeDesc, "code_desc should not be empty for requirement %s", req.ID)
		}
	}
}

// ---- CWE → NIST mapping ----

func TestConvertJfrogXray_CweToNist(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// All requirements should have nist tags (either mapped or fallback)
	for _, req := range reqs {
		nist := hdfutil.SafeStringSlice(req.Tags["nist"])
		require.NotNil(t, nist, "nist tag should be present for requirement %s", req.ID)
		assert.NotEmpty(t, nist, "nist tag should not be empty for requirement %s", req.ID)
	}
}

// ---- CWE tag populated when present ----

func TestConvertJfrogXray_CweTag(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// At least one requirement should have a cweid tag (fixture has CWE-74, CWE-835, CWE-668, etc.)
	hasCWE := false
	for _, req := range reqs {
		if cweSlice, ok := req.Tags["cweid"]; ok && cweSlice != nil {
			hasCWE = true
			break
		}
	}
	assert.True(t, hasCWE, "expected at least one requirement with cweid tag")
}

// ---- Title from summary ----

func TestConvertJfrogXray_Title(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		require.NotNil(t, req.Title, "title should not be nil for requirement %s", req.ID)
		assert.NotEmpty(t, *req.Title, "title should not be empty for requirement %s", req.ID)
	}
}

// ---- Empty data array ----

func TestConvertJfrogXray_EmptyData(t *testing.T) {
	input := []byte(`{
		"total_count": 0,
		"data": []
	}`)
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Len(t, result.Baselines[0].Requirements, 0)
}

// ---- Severity helper ----

func TestGetImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"High", 0.7},
		{"high", 0.7},
		{"Medium", 0.5},
		{"medium", 0.5},
		{"Low", 0.3},
		{"low", 0.3},
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
	shared.RunSnapshotTests(t, "jfrog-xray-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertJfrogXrayToHDF(input, "0.1.0")
	})
}
