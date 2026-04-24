package veracode

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "veracode-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read fixture: %s", name)
	return data
}

func TestConvertVeracodeToHDF_Sample(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "veracode-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)

	// Verify tool
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Veracode", *result.Tool.Name)

	// Should have exactly 1 baseline
	require.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Veracode Scan", baseline.Name)

	// Should have target
	require.Len(t, result.Components, 1)
	assert.Equal(t, hdf.CopyrightApplication, result.Components[0].Type)

	// CWE-based controls: 14 categories (categoryid 12 appears at both severity 3 and 2)
	// CVE-based controls: 39 unique CVEs = 53 total
	totalRequirements := len(baseline.Requirements)
	assert.Greater(t, totalRequirements, 0, "Should have requirements")

	// Write output for differential testing
	shared.WriteOutput(t, "veracode-to-hdf", "veracode.json", result)
}

func TestConvertVeracodeToHDF_CWEControls(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]

	// Find a CWE-based control: categoryid "18" = "Command or Argument Injection"
	var cweControl *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "18" {
			cweControl = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, cweControl, "Should have CWE control with categoryid 18")
	require.NotNil(t, cweControl.Title)
	assert.Equal(t, "Command or Argument Injection", *cweControl.Title)

	// Severity level 5 maps to impact 0.9
	assert.Equal(t, 0.9, cweControl.Impact)

	// Should have results (static flaws)
	assert.Greater(t, len(cweControl.Results), 0, "Should have flaw results")
	// All results should be Failed
	for _, r := range cweControl.Results {
		assert.Equal(t, hdf.Failed, r.Status)
	}

	// Should have NIST tags from CWE mapping
	nistTags, ok := cweControl.Tags["nist"]
	assert.True(t, ok, "Should have nist tags")
	assert.NotEmpty(t, nistTags, "NIST tags should not be empty")

	// Should have descriptions
	assert.Greater(t, len(cweControl.Descriptions), 0, "Should have descriptions")
}

func TestConvertVeracodeToHDF_CVEControls(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]

	// Find a CVE-based control
	var cveControl *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "CVE-2017-1000487" {
			cveControl = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, cveControl, "Should have CVE control CVE-2017-1000487")
	require.NotNil(t, cveControl.Title)
	assert.Equal(t, "CVE-2017-1000487", *cveControl.Title)

	// Should have impact mapped from severity
	assert.Greater(t, cveControl.Impact, 0.0, "Should have non-zero impact")

	// Should have at least one failed result (one per affected component)
	assert.Greater(t, len(cveControl.Results), 0)
	for _, r := range cveControl.Results {
		assert.Equal(t, hdf.Failed, r.Status)
	}

	// Should have NIST tags
	nistTags, ok := cveControl.Tags["nist"]
	assert.True(t, ok, "Should have nist tags")
	assert.NotEmpty(t, nistTags, "NIST tags should not be empty")
}

func TestConvertVeracodeToHDF_SeverityImpactMapping(t *testing.T) {
	tests := []struct {
		level    string
		expected float64
	}{
		{"5", 0.9},
		{"4", 0.7},
		{"3", 0.5},
		{"2", 0.3},
		{"1", 0.1},
		{"0", 0.0},
	}

	for _, tt := range tests {
		t.Run("level_"+tt.level, func(t *testing.T) {
			got := veracodeSeverityToImpact(tt.level)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "veracode-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertVeracodeToHDF(input, testConverterVersion) },
		MinimalFixture: "veracode.xml",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertVeracodeToHDF_SummaryReport(t *testing.T) {
	summaryXML := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>
<summaryreport xmlns="https://www.veracode.com/schema/reports/export/1.0">
</summaryreport>`)

	result, err := ConvertVeracodeToHDF(summaryXML, testConverterVersion)
	assert.Error(t, err, "Should reject summary reports")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "summary")
}

func TestConvertVeracodeToHDF_ResultsChecksum(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	// Each baseline should have a results checksum
	assert.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

func TestConvertVeracodeToHDF_Timestamp(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.NotNil(t, result.Timestamp, "Should have timestamp from first_build_submitted_date")
}

func TestConvertVeracodeToHDF_AllFlawsAccountedFor(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	baseline := result.Baselines[0]

	// Count total results across all requirements
	totalResults := 0
	cweControlCount := 0
	cveControlCount := 0
	for _, req := range baseline.Requirements {
		totalResults += len(req.Results)
		// CVE controls have IDs starting with "CVE-" or "SRCCLR-"
		if len(req.ID) > 4 && (req.ID[:4] == "CVE-" || req.ID[:7] == "SRCCLR-") {
			cveControlCount++
		} else {
			cweControlCount++
		}
	}

	// The fixture has 194 static flaws + 41 SCA vulnerabilities
	// CWE controls: 14 categories (categoryid 12 appears at severity 3 and 2)
	// CVE controls: 39 unique CVEs (grouped by cve_id across components)
	assert.Equal(t, 14, cweControlCount, "Should have 14 CWE-based controls (categoryid 12 appears at 2 severity levels)")
	assert.Equal(t, 39, cveControlCount, "Should have 39 CVE-based controls")

	// Total flaw results from CWE controls should be 194
	cweResultCount := 0
	for _, req := range baseline.Requirements {
		if len(req.ID) <= 4 || (req.ID[:4] != "CVE-" && (len(req.ID) < 7 || req.ID[:7] != "SRCCLR-")) {
			cweResultCount += len(req.Results)
		}
	}
	assert.Equal(t, 194, cweResultCount, "CWE controls should have 194 total flaw results")
}

func TestConvertVeracodeToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertVeracodeToHDF(input, testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "veracode-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertVeracodeToHDF(input, "0.1.0")
	})
}
