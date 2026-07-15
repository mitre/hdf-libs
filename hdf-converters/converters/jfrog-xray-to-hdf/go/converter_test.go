package jfrogxray

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
	assert.Equal(t, hdf.Application, result.Components[0].Type)
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

func TestConvertJfrogXray_EmptyDataSynthesizesPlaceholder(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1, "empty-findings input must synthesize a single placeholder requirement")

	req := reqs[0]
	assert.Equal(t, "jfrog-xray-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)

	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "JFrog Xray")
	assert.Contains(t, codeDesc, "zero vulnerable components")
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
	// JFrog Xray export carries no scan time.
	shared.RunSnapshotTests(t, "jfrog-xray-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertJfrogXrayToHDF(input, "1.0.0")
	}, "*")
}

func TestConvertJfrogXrayToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

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

func TestConvertJfrogXray_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: JFrog Xray is an automated vulnerability scanner", req.ID)
	}
}

// countDistinctEntryIDs derives the ground-truth requirement count directly from
// the raw JSON, independent of the converter's structs: JFrog Xray groups
// data[] entries by their effective ID (the entry's id, or its summary when id
// is empty) and emits one requirement per group. A plain data[] count would
// over-count merged duplicates, so the grouping is re-derived here rather than
// reusing the converter's traversal.
func countDistinctEntryIDs(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Data []struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "anchor: invalid jfrog-xray JSON")
	seen := map[string]bool{}
	for _, e := range doc.Data {
		key := e.ID
		if key == "" {
			key = "summary:" + e.Summary
		}
		seen[key] = true
	}
	return len(seen)
}

// Ground-truth anchor: one requirement per distinct effective entry ID. Catches
// a silent under-extraction that TS/Go golden parity cannot see.
func TestConvertJfrogXray_EntryAnchor(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctEntryIDs(t, input),
		"jfrog_xray_sample.json: one requirement per distinct data[] entry ID")
}
