package fortify

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	inputPath := filepath.Join(shared.GetConvertersDir(), "fortify-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read fixture: %s", name)
	return data
}

func findRequirementByID(requirements []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range requirements {
		if requirements[i].ID == id {
			return &requirements[i]
		}
	}
	return nil
}

func TestConvertFortifyToHDF_ControlType(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")
	result, err := ConvertFortifyToHDF(inputData, converterVersion)
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

func TestConvertFortifyToHDF_Sample(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "fortify-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)

	// Verify baselines — one baseline per FVDL file
	require.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Fortify Scan", baseline.Name)

	// Verify that requirements exist — one per unique Description classID
	// The fixture has 5 unique Description classIDs
	assert.Len(t, baseline.Requirements, 5, "Should have 5 requirements (one per Description classID)")

	// Verify targets
	require.Len(t, result.Components, 1, "Should have 1 target")
	assert.Equal(t, hdf.Repository, result.Components[0].Type)

	// Write output for differential testing
	shared.WriteOutput(t, "fortify-to-hdf", "fortify_webgoat_results.json", result)
}

func TestConvertFortifyToHDF_BaselineMetadata(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Title should contain "Fortify Static Analyzer Scan"
	require.NotNil(t, baseline.Title)
	assert.Contains(t, *baseline.Title, "Fortify Static Analyzer Scan")

	// Summary should contain UUID
	require.NotNil(t, baseline.Summary)
	assert.Contains(t, *baseline.Summary, "b5e71375-1a97-4708-a07e-9a7e5fedeafe")

	// Version should be engine version
	require.NotNil(t, baseline.Version)
	assert.Equal(t, "19.1.0.2241", *baseline.Version)

	// ResultsChecksum should be populated
	require.NotNil(t, baseline.ResultsChecksum)
	assert.Equal(t, hdf.Sha256, baseline.ResultsChecksum.Algorithm)
	assert.Len(t, baseline.ResultsChecksum.Value, 64, "SHA-256 hash should be 64 hex chars")
}

func TestConvertFortifyToHDF_Tool(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Fortify", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "FVDL", *result.Tool.Format)
}

func TestConvertFortifyToHDF_RequirementFields(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Find the "Path Manipulation" requirement (classID 823FE039-...)
	pathManip := findRequirementByID(baseline.Requirements, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59")
	require.NotNil(t, pathManip, "Should find Path Manipulation requirement")

	// ID is the classID
	assert.Equal(t, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59", pathManip.ID)

	// Title comes from Abstract (HTML stripped)
	require.NotNil(t, pathManip.Title)
	assert.NotEmpty(t, *pathManip.Title)
	assert.NotContains(t, *pathManip.Title, "<Content>")

	// Impact derived from DefaultSeverity / 5
	// DefaultSeverity=3.0 -> 3.0/5 = 0.6
	assert.Equal(t, 0.6, pathManip.Impact)

	// Should have descriptions with label "default" from Explanation
	require.Greater(t, len(pathManip.Descriptions), 0, "Should have descriptions")
	foundDefault := false
	for _, desc := range pathManip.Descriptions {
		if desc.Label == "default" {
			foundDefault = true
			assert.NotEmpty(t, desc.Data)
			assert.NotContains(t, desc.Data, "<Content>")
		}
	}
	assert.True(t, foundDefault, "Should have a default description")

	// Should have results — one per vulnerability with this classID
	assert.Greater(t, len(pathManip.Results), 0, "Should have results")
	for _, res := range pathManip.Results {
		assert.Equal(t, hdf.Failed, res.Status)
		assert.NotEmpty(t, res.CodeDesc)
	}
}

func TestConvertFortifyToHDF_NISTTags(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// The Path Manipulation description has a NIST reference "SI-10" in its References
	pathManip := findRequirementByID(baseline.Requirements, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59")
	require.NotNil(t, pathManip)

	tags := pathManip.Tags
	require.NotNil(t, tags, "Tags should not be nil")
	nist, ok := tags["nist"]
	assert.True(t, ok, "Should have nist tag")
	nistSlice, ok := nist.([]interface{})
	assert.True(t, ok, "nist should be a slice")
	assert.Greater(t, len(nistSlice), 0, "Should have at least one NIST tag")
}

func TestConvertFortifyToHDF_SnippetInCodeDesc(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Check that at least one requirement has results with snippet-based code descriptions
	foundSnippet := false
	for _, req := range baseline.Requirements {
		for _, res := range req.Results {
			if res.CodeDesc != "" {
				foundSnippet = true
				break
			}
		}
		if foundSnippet {
			break
		}
	}
	assert.True(t, foundSnippet, "At least one result should have a code description")
}

func TestConvertFortifyToHDF_Timestamp(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2019, result.Timestamp.Year())
	assert.Equal(t, 10, int(result.Timestamp.Month()))
	assert.Equal(t, 2, result.Timestamp.Day())
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "fortify-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertFortifyToHDF(input, converterVersion) },
		MinimalFixture: "fortify_webgoat_results.fvdl",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertFortifyToHDF_MinimalFVDL(t *testing.T) {
	minimalFVDL := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<CreatedTS date="2024-01-15" time="10:00:00"/>
<UUID>test-uuid-1234</UUID>
<Build>
  <BuildID>test</BuildID>
  <NumberFiles>0</NumberFiles>
  <SourceBasePath>/tmp/test</SourceBasePath>
  <SourceFiles/>
</Build>
<Vulnerabilities/>
<Description contentType="preformatted" classID="TEST-001">
  <Abstract>Test abstract</Abstract>
  <Explanation>Test explanation</Explanation>
  <Recommendations>Test recommendations</Recommendations>
  <References/>
</Description>
<Snippets/>
<EngineData>
  <EngineVersion>20.0.0</EngineVersion>
  <RulePacks/>
  <Properties type="System"/>
  <CommandLine/>
  <Errors/>
  <MachineInfo/>
</EngineData>
</FVDL>`)

	result, err := ConvertFortifyToHDF(minimalFVDL, converterVersion)
	require.NoError(t, err, "Minimal FVDL should convert successfully")
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "Fortify Scan", baseline.Name)
	// With 1 description but 0 vulnerabilities matching, should have 1 requirement with 0 results
	assert.Len(t, baseline.Requirements, 1)
}

func TestConvertFortifyToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertFortifyToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "fortify-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertFortifyToHDF(input, "0.1.0")
	})
}

func TestConvertFortifyToHDF_VerificationMethod(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")
	result, err := ConvertFortifyToHDF(inputData, converterVersion)
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
