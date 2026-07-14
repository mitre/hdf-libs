package dbprotect

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
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
	path := filepath.Join(shared.GetConvertersDir(), "dbprotect-to-hdf", "fixtures", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "dbprotect-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertDbprotectToHDF(input, testVersion) },
		MinimalFixture: "sample-check-results.xml",
		InvalidInput:   "<not valid xml",
	})
}

// ---- Check Results Details fixture ----

func TestConvertDbprotect_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
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
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

func TestConvertDbprotect_CheckResults_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "dbprotect-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)

	// Should have one baseline
	require.Len(t, result.Baselines, 1)

	// Should have tool
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "DBProtect", *result.Tool.Name)
}

func TestConvertDbprotect_CheckResults_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "DBProtect Scan", result.Baselines[0].Name)
}

func TestConvertDbprotect_CheckResults_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Title comes from first row's "Job Name"
	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "Heimdal Test scan report generation")
}

func TestConvertDbprotect_CheckResults_BaselineSummary(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Contains(t, *result.Baselines[0].Summary, "Organization")
	assert.Contains(t, *result.Baselines[0].Summary, "CONDS181")
}

func TestConvertDbprotect_CheckResults_Checksum(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Regexp(t, `^[a-f0-9]{64}$`, result.Baselines[0].ResultsChecksum.Value)
}

func TestConvertDbprotect_CheckResults_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// 8 rows with 6 unique Check IDs: 2986 (2 rows), 2903, 2841, 2801 (2 rows), 2942, 2976
	assert.Len(t, result.Baselines[0].Requirements, 6)
}

// countDistinctCheckIDs parses the raw Cognos XML generically — deliberately NOT
// the converter's structs — and returns the number of distinct "Check ID"
// values across all data rows. It locates the "Check ID" column by its position
// in <metadata><item> and reads the value at that index in each <data><row>.
// The converter emits one requirement per distinct Check ID (rows sharing an id
// are grouped), so the distinct count — not the raw row count — is the ground
// truth.
func countDistinctCheckIDs(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Metadata struct {
			Items []struct {
				Name string `xml:"name,attr"`
			} `xml:"item"`
		} `xml:"metadata"`
		Data struct {
			Rows []struct {
				Values []string `xml:"value"`
			} `xml:"row"`
		} `xml:"data"`
	}
	require.NoError(t, xml.Unmarshal(input, &doc), "failed to parse DBProtect XML for anchor count")

	idx := -1
	for i, item := range doc.Metadata.Items {
		if item.Name == "Check ID" {
			idx = i
			break
		}
	}
	require.GreaterOrEqual(t, idx, 0, "fixture lacks a Check ID column")

	distinct := make(map[string]struct{})
	for _, row := range doc.Data.Rows {
		if idx < len(row.Values) {
			distinct[strings.TrimSpace(row.Values[idx])] = struct{}{}
		}
	}
	return len(distinct)
}

// Ground-truth anchor: one requirement per distinct Check ID. Counted
// independently of the converter so a silent under-extraction fails even when Go
// and TS goldens agree.
func TestConvertDbprotect_CheckResults_DistinctCheckIDAnchor(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	shared.AssertRequirementCount(t, result, countDistinctCheckIDs(t, input),
		"sample-check-results.xml: one requirement per distinct Check ID")
}

func TestConvertDbprotect_CheckResults_GroupedResults(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2986 appears twice, should have 2 results
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	assert.Len(t, req.Results, 2)

	// Check ID 2801 appears twice, should have 2 results
	req2801 := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	assert.Len(t, req2801.Results, 2)
}

func TestConvertDbprotect_CheckResults_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Schema ownership", *req.Title)
}

func TestConvertDbprotect_CheckResults_RequirementDescription(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Descriptions)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	// Description from formatDesc: "Task : <task>; Check Category : <category>"
	assert.Contains(t, req.Descriptions[0].Data, "Task")
	assert.Contains(t, req.Descriptions[0].Data, "Check Category")
}

// ---- Impact mapping ----

func TestConvertDbprotect_CheckResults_HighImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2903")
	assert.Equal(t, 0.7, req.Impact)
}

func TestConvertDbprotect_CheckResults_MediumImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	assert.Equal(t, 0.5, req.Impact)
}

func TestConvertDbprotect_CheckResults_LowImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2841")
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertDbprotect_CheckResults_InformationalImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	assert.Equal(t, 0.0, req.Impact)
}

// ---- Status mapping ----

func TestConvertDbprotect_CheckResults_FactStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2986 has "Fact" status -> Skipped/NotReviewed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_FailedStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2841 has "Failed" status -> Failed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2841")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_FindingStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2801 has "Finding" status -> Failed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_NotAFindingStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2942 has "Not A Finding" status -> Passed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2942")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_SkippedStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2976 has "Skipped" status -> NotReviewed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2976")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
}

// ---- CodeDesc and start time ----

func TestConvertDbprotect_CheckResults_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// CodeDesc comes from the "Details" column
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "Schema name=DatabaseMailUserRole")
}

func TestConvertDbprotect_CheckResults_StartTime(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Results)
	assert.False(t, req.Results[0].StartTime.IsZero(), "StartTime should be set")
}

// ---- NIST tags ----

func TestConvertDbprotect_CheckResults_NISTTags(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotNil(t, req.Tags)
	nist, ok := req.Tags["nist"]
	require.True(t, ok, "Should have nist tag")
	nistSlice := hdfutil.SafeStringSlice(nist)
	assert.NotEmpty(t, nistSlice, "NIST tags should not be empty")
}

// ---- Target ----

func TestConvertDbprotect_CheckResults_Target(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "CONDS181", result.Components[0].Name)
	assert.Equal(t, hdf.Host, result.Components[0].Type)
}

// ---- Findings Detail fixture ----

func TestConvertDbprotect_FindingsDetail_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "DBProtect Scan", result.Baselines[0].Name)
}

func TestConvertDbprotect_FindingsDetail_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// 4 rows with 3 unique Check IDs: 2801 (2 rows), 2830, 2903
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertDbprotect_FindingsDetail_AllFindingsAreFailed(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Findings Detail has no Result Status column; all findings are implicitly failed
	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status, "All findings should be failed for check %s", req.ID)
		}
	}
}

// ---- Write output for differential testing ----

func TestConvertDbprotect_WriteOutput(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	shared.WriteOutput(t, "dbprotect-to-hdf", "sample-check-results.json", result)
}

func TestConvertDbprotectToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertDbprotectToHDF(input, testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "dbprotect-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertDbprotectToHDF(input, "1.0.0")
	})
}

func TestConvertDbprotect_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "every requirement must have verificationMethod set")
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q should be marked automated", req.ID)
	}
}
