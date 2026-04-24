//nolint:dupl
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const (
	oscalFixtureDir = "../../../../hdf-converters/converters/oscal-to-hdf/fixtures/input"
)

func TestConvertOSCALCatalog(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "catalog-moderate-resolved.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-catalog", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var baseline hdf.HDFBaseline
	err = json.Unmarshal(data, &baseline)
	require.NoError(t, err)

	assert.Equal(t, 287, len(baseline.Requirements))
	assert.NotEmpty(t, baseline.Name)
	assert.NotNil(t, baseline.Generator)
}

func TestConvertOSCALProfile(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	catalogPath := filepath.Join(oscalFixtureDir, "catalog-800-53-rev5.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}
	if _, err := os.Stat(catalogPath); err != nil {
		t.Skip("OSCAL catalog fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")

	// Reset flag for test isolation
	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-profile", "--to", "hdf", profilePath, "-o", output, "--catalog", catalogPath})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var baseline hdf.HDFBaseline
	err = json.Unmarshal(data, &baseline)
	require.NoError(t, err)

	assert.Equal(t, 287, len(baseline.Requirements))
	assert.NotNil(t, baseline.Title)
	assert.Contains(t, *baseline.Title, "MODERATE")
}

func TestConvertOSCALProfile_NoCatalogFlag(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}

	// Reset flag for test isolation
	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-profile", "--to", "hdf", profilePath})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--catalog flag is required")
}

func TestConvertOSCALProfile_BadCatalogPath(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}

	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-profile", "--to", "hdf", profilePath, "--catalog", "/nonexistent/catalog.json"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read catalog")
}

func TestConvertOSCALComponentDefinition(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "component-example.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL component-definition fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-component-definition", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var baseline hdf.HDFBaseline
	err = json.Unmarshal(data, &baseline)
	require.NoError(t, err)

	assert.NotEmpty(t, baseline.Name)
	assert.NotEmpty(t, baseline.Requirements)
	assert.NotNil(t, baseline.Generator)
}

func TestConvertOSCALSSP(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "ssp-example.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL SSP fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-ssp", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var system hdf.HDFSystem
	err = json.Unmarshal(data, &system)
	require.NoError(t, err)

	assert.Equal(t, "Enterprise Logging and Auditing System", system.Name)
	assert.NotEmpty(t, system.Components)
	assert.NotNil(t, system.Generator)
}

func TestConvertOSCALAssessmentPlan(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "sap-fedramp.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL SAP fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-assessment-plan", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var plan hdf.HDFPlan
	err = json.Unmarshal(data, &plan)
	require.NoError(t, err)

	assert.NotEmpty(t, plan.Name)
	assert.Contains(t, plan.Name, "fedramp")
	assert.NotEmpty(t, plan.Assessments)
	assert.NotNil(t, plan.SystemRef)
	assert.NotNil(t, plan.Generator)
}

func TestConvertOSCALAssessmentResults(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "sar-fedramp.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL SAR fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-assessment-results", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var results hdf.HDFResults
	err = json.Unmarshal(data, &results)
	require.NoError(t, err)

	assert.NotEmpty(t, results.Baselines)
	assert.NotEmpty(t, results.Baselines[0].Requirements)
	assert.NotNil(t, results.Generator)
	assert.Equal(t, "oscal-assessment-results-to-hdf", results.Generator.Name)
	assert.NotNil(t, results.Tool)
}

func TestConvertOSCALAssessmentResults_SARAlias(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "sar-fedramp.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL SAR fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-sar", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var results hdf.HDFResults
	err = json.Unmarshal(data, &results)
	require.NoError(t, err)

	assert.NotEmpty(t, results.Baselines)
}

func TestConvertOSCALPOAM(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "poam-fedramp.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL POAM fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal-poam", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var amendments hdf.HDFAmendments
	err = json.Unmarshal(data, &amendments)
	require.NoError(t, err)

	assert.NotEmpty(t, amendments.Name)
	assert.Contains(t, amendments.Name, "fedramp")
	assert.NotEmpty(t, amendments.Overrides)
	assert.NotNil(t, amendments.SystemRef)
	assert.NotNil(t, amendments.Generator)

	// All overrides should be type "poam"
	for _, override := range amendments.Overrides {
		assert.Equal(t, hdf.Poam, override.Type)
	}
}

func TestConvertOSCALAutoDetect_Catalog(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "catalog-moderate-resolved.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var baseline hdf.HDFBaseline
	require.NoError(t, json.Unmarshal(data, &baseline))
	assert.NotEmpty(t, baseline.Requirements)
}

func TestConvertOSCALAutoDetect_SAR(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "sar-fedramp.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal", "--to", "hdf", inputPath, "-o", output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	assert.NotEmpty(t, results.Baselines)
}

func TestConvertOSCALAutoDetect_InvalidInput(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "invalid.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{"not-oscal": true}`), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal", "--to", "hdf", tmpFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oscal auto-detect")
}

func TestConvertHDFToOSCALSAR(t *testing.T) {
	// First convert SAR to HDF to get a valid HDF fixture
	sarPath := filepath.Join(oscalFixtureDir, "sar-fedramp.json")
	if _, err := os.Stat(sarPath); err != nil {
		t.Skip("OSCAL SAR fixture not available")
	}

	tmpDir := t.TempDir()
	hdfPath := filepath.Join(tmpDir, "intermediate.json")

	// SAR -> HDF
	cmd1 := NewRootCmd()
	cmd1.SetArgs([]string{"convert", "--from", "oscal-sar", "--to", "hdf", sarPath, "-o", hdfPath})
	require.NoError(t, cmd1.Execute())

	// HDF -> OSCAL SAR
	outputPath := filepath.Join(tmpDir, "output-sar.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"convert", "--from", "hdf", "--to", "oscal-sar", hdfPath, "-o", outputPath})

	err := cmd2.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	// Verify it's valid OSCAL SAR JSON
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Contains(t, raw, "assessment-results")
}

func TestConvertHDFToOSCALSAR_MinimalInline(t *testing.T) {
	// Create minimal HDF inline
	hdfJSON := `{
		"baselines": [{
			"name": "test-baseline",
			"requirements": [{
				"id": "AC-1",
				"impact": 0.5,
				"tags": {"nist": ["AC-1"]},
				"descriptions": [{"label": "default", "data": "Test"}],
				"results": [{"status": "passed", "codeDesc": "test", "startTime": "2024-01-01T00:00:00Z"}]
			}]
		}]
	}`

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	require.NoError(t, os.WriteFile(inputPath, []byte(hdfJSON), 0o600))

	outputPath := filepath.Join(tmpDir, "output.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "hdf", "--to", "oscal-sar", inputPath, "-o", outputPath})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Contains(t, raw, "assessment-results")
}
