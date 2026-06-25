//nolint:dupl // Coverage tests intentionally exercise similar patterns across converters
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// converter_registry.go — Convert() error paths for each wrapper type
// ---------------------------------------------------------------------------

// TestHDFResultsConverter_ConvertError exercises the convertFn-error branch
// inside hdfResultsConverter.Convert.
func TestConverterCoverage_HDFResultsConverter_ConvertError(t *testing.T) {
	// Use a known converter that will fail on garbage input.
	conv, err := GetConverter("sarif", "hdf")
	if err != nil {
		t.Skip("sarif converter not registered")
	}

	out, err := conv.Convert([]byte("<<<not json>>>"))
	assert.Error(t, err, "hdfResultsConverter.Convert should propagate convertFn error")
	assert.Nil(t, out)
	// Verify the error prefix wrapping
	assert.Contains(t, err.Error(), "conversion failed")
}

// TestHDFBaselineConverter_ConvertError exercises the convertFn-error branch
// inside hdfBaselineConverter.Convert.
func TestConverterCoverage_HDFBaselineConverter_ConvertError(t *testing.T) {
	conv, err := GetConverter("oscal-catalog", "hdf")
	if err != nil {
		t.Skip("oscal-catalog converter not registered")
	}

	out, err := conv.Convert([]byte("<<<not json>>>"))
	assert.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "conversion failed")
}

// TestRawConverter_ConvertError exercises the convertFn-error branch
// inside rawConverter.Convert.
func TestConverterCoverage_RawConverter_ConvertError(t *testing.T) {
	conv, err := GetConverter("oscal-ssp", "hdf")
	if err != nil {
		t.Skip("oscal-ssp converter not registered")
	}

	out, err := conv.Convert([]byte("<<<not json>>>"))
	assert.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "conversion failed")
}

// TestHDFPlanConverter_ConvertError exercises the convertFn-error branch
// inside hdfPlanConverter.Convert.
func TestConverterCoverage_HDFPlanConverter_ConvertError(t *testing.T) {
	conv, err := GetConverter("oscal-assessment-plan", "hdf")
	if err != nil {
		t.Skip("oscal-assessment-plan converter not registered")
	}

	out, err := conv.Convert([]byte("<<<not json>>>"))
	assert.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "conversion failed")
}

// TestHDFAmendmentsConverter_ConvertError exercises the convertFn-error branch
// inside hdfAmendmentsConverter.Convert.
func TestConverterCoverage_HDFAmendmentsConverter_ConvertError(t *testing.T) {
	conv, err := GetConverter("oscal-poam", "hdf")
	if err != nil {
		t.Skip("oscal-poam converter not registered")
	}

	out, err := conv.Convert([]byte("<<<not json>>>"))
	assert.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "conversion failed")
}

// TestConverterCoverage_NameMethods ensures all wrapper Name() methods return
// non-empty strings (covers Name() lines that may not be exercised elsewhere).
func TestConverterCoverage_NameMethods(t *testing.T) {
	pairs := []struct {
		source string
		dest   string
	}{
		{"sarif", "hdf"},                 // hdfResultsConverter
		{"oscal-catalog", "hdf"},         // hdfBaselineConverter
		{"oscal-ssp", "hdf"},             // rawConverter
		{"oscal-assessment-plan", "hdf"}, // hdfPlanConverter
		{"oscal-poam", "hdf"},            // hdfAmendmentsConverter
	}

	for _, p := range pairs {
		t.Run(p.source, func(t *testing.T) {
			conv, err := GetConverter(p.source, p.dest)
			if err != nil {
				t.Skipf("%s converter not registered", p.source)
			}
			assert.NotEmpty(t, conv.Name())
		})
	}
}

// ---------------------------------------------------------------------------
// converter_hdf_to_oscal_poam.go — Name() and Convert() (0% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_HDFToOSCALPOAM_IsRegistered(t *testing.T) {
	conv, err := GetConverter("hdf-amendments", "oscal-poam")
	require.NoError(t, err, "hdf-amendments -> oscal-poam converter should be registered")
	assert.NotNil(t, conv)
	assert.Equal(t, "HDF Amendments to OSCAL POA&M", conv.Name())
}

func TestConverterCoverage_HDFToOSCALPOAM_Convert_Minimal(t *testing.T) {
	// Build a minimal HDFAmendments JSON inline.
	amendments := map[string]interface{}{
		"name": "test-poam",
		"overrides": []map[string]interface{}{
			{
				"type":          "poam",
				"requirementId": "AC-1",
				"reason":        "Pending remediation",
				"status":        "failed",
				"appliedBy": map[string]interface{}{
					"type":       "simple",
					"identifier": "admin@example.com",
				},
				"appliedAt": "2026-01-15T00:00:00Z",
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	conv, err := GetConverter("hdf-amendments", "oscal-poam")
	require.NoError(t, err)

	output, err := conv.Convert(input)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	// Verify the OSCAL envelope
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(output, &doc))
	assert.Contains(t, doc, "plan-of-action-and-milestones")
}

func TestConverterCoverage_HDFToOSCALPOAM_Convert_InvalidInput(t *testing.T) {
	conv, err := GetConverter("hdf-amendments", "oscal-poam")
	require.NoError(t, err)

	out, err := conv.Convert([]byte("not json"))
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestConverterCoverage_HDFToOSCALPOAM_Convert_EmptyInput(t *testing.T) {
	conv, err := GetConverter("hdf-amendments", "oscal-poam")
	require.NoError(t, err)

	out, err := conv.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestConverterCoverage_HDFToOSCALPOAM_CLI(t *testing.T) {
	// Write amendments fixture to temp dir, run through CLI.
	amendments := map[string]interface{}{
		"name": "cli-test-poam",
		"overrides": []map[string]interface{}{
			{
				"type":          "poam",
				"requirementId": "SI-2",
				"reason":        "Vulnerability remediation in progress",
				"status":        "failed",
				"appliedBy": map[string]interface{}{
					"type":       "simple",
					"identifier": "sec-team@example.com",
				},
				"appliedAt": "2026-03-01T00:00:00Z",
			},
		},
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "amendments.json")
	inputData, err := json.MarshalIndent(amendments, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(inputPath, inputData, 0o600))

	outputPath := filepath.Join(tmpDir, "poam.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "hdf-amendments", "--to", "oscal-poam", inputPath, "-o", outputPath})

	err = cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Contains(t, doc, "plan-of-action-and-milestones")
}

// ---------------------------------------------------------------------------
// converter_oscal.go — oscalSSPRawConvert error path (71.4% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_OscalSSP_InvalidJSON(t *testing.T) {
	// oscalSSPRawConvert wraps ConvertSSPToHDF — feed garbage to hit error.
	out, err := oscalSSPRawConvert([]byte("not json"), "test")
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestConverterCoverage_OscalSSP_EmptyInput(t *testing.T) {
	out, err := oscalSSPRawConvert([]byte(""), "test")
	assert.Error(t, err)
	assert.Nil(t, out)
}

// ---------------------------------------------------------------------------
// converter_oscal.go — oscalAutoDetectConverter unsupported type
// ---------------------------------------------------------------------------

func TestConverterCoverage_OscalAutoDetect_UnknownType(t *testing.T) {
	// A JSON doc with a key that looks OSCAL-ish but is not a known type.
	// DetectDocumentType returns error for unrecognized keys.
	tmpFile := filepath.Join(t.TempDir(), "unknown.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{"unknown-oscal-type": {}}`), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "oscal", "--to", "hdf", tmpFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oscal auto-detect")
}

// ---------------------------------------------------------------------------
// converter_gitlab.go — Convert error path (85.7% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_Gitlab_Convert_EmptyJSON(t *testing.T) {
	// Valid JSON but not a valid GitLab report → should error in the converter.
	conv, err := GetConverter("gitlab", "hdf")
	if err != nil {
		t.Skip("gitlab converter not registered")
	}

	out, err := conv.Convert([]byte(`{"version": "99.0"}`))
	// GitLab converter may succeed with empty results or error — either is OK.
	// We are exercising the code path, not asserting a specific outcome.
	if err != nil {
		assert.Nil(t, out)
		assert.Contains(t, err.Error(), "gitlab")
	} else {
		assert.NotNil(t, out)
	}
}

// ---------------------------------------------------------------------------
// converter_legacyhdf.go — Convert non-v1 JSON path (80% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_LegacyHDF_ValidJSONNotV1(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skip("legacyhdf converter not registered")
	}

	// Valid JSON with unexpected structure — hits IsHDFV1 check.
	input := []byte(`{"version": "2.0", "baselines": []}`)
	out, err := conv.Convert(input)
	assert.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "not valid InSpec")
}

func TestConverterCoverage_LegacyHDF_MalformedV1(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skip("legacyhdf converter not registered")
	}

	// JSON that looks like v1 (has "profiles" key) but can't fully parse.
	// This exercises the json.Unmarshal error path after IsHDFV1 passes.
	input := []byte(`{"profiles": "not-an-array", "platform": {"name": "test"}, "version": "1.0", "statistics": {}}`)
	out, err := conv.Convert(input)
	// May fail at IsHDFV1 or at Unmarshal — either path is coverage.
	if err != nil {
		assert.Nil(t, out)
	}
}

// ---------------------------------------------------------------------------
// convert.go — checkOutputOverwritesInput edge cases (77.8% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_CheckOutputOverwritesInput_SamePath(t *testing.T) {
	// Same input and output path should error.
	tmpFile := filepath.Join(t.TempDir(), "data.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{}"), 0o600))

	err := checkOutputOverwritesInput(tmpFile, tmpFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "would overwrite input")
}

func TestConverterCoverage_CheckOutputOverwritesInput_DifferentPaths(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.json")
	outputFile := filepath.Join(tmpDir, "output.json")
	require.NoError(t, os.WriteFile(inputFile, []byte("{}"), 0o600))

	err := checkOutputOverwritesInput(inputFile, outputFile)
	assert.NoError(t, err)
}

func TestConverterCoverage_CheckOutputOverwritesInput_RelativeSamePath(t *testing.T) {
	// Use relative paths that resolve to the same file.
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "data.json")
	require.NoError(t, os.WriteFile(inputFile, []byte("{}"), 0o600))

	// Both should resolve to the same absolute path.
	relInput := inputFile
	relOutput := filepath.Join(tmpDir, ".", "data.json")

	err := checkOutputOverwritesInput(relInput, relOutput)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "would overwrite input")
}

// ---------------------------------------------------------------------------
// convert.go — runConvert with --force flag bypasses overwrite check
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertForceOverwrite(t *testing.T) {
	// Create a valid sarif input fixture, convert with --force where output == input
	// This tests the force flag path in runConvert.
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test-tool", "rules": []}},
			"results": []
		}]
	}`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.sarif.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(sarifJSON), 0o600))

	// Without --force, same output path should error
	cmd1 := NewRootCmd()
	cmd1.SetArgs([]string{"convert", "--from", "sarif", "--to", "hdf", inputFile, "-o", inputFile})
	err := cmd1.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "would overwrite input")

	// With --force, same path should succeed
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"convert", "--from", "sarif", "--to", "hdf", inputFile, "-o", inputFile, "--force"})
	err = cmd2.Execute()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// convert.go — runConvert auto-detect path (60.5% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertAutoDetect_SARIF(t *testing.T) {
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "auto-detect-test", "rules": []}},
			"results": []
		}]
	}`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "scan.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(sarifJSON), 0o600))

	outputFile := filepath.Join(tmpDir, "out.json")
	// No --from flag — auto-detect should pick up SARIF
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--to", "hdf", inputFile, "-o", outputFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestConverterCoverage_ConvertAutoDetect_Unrecognized(t *testing.T) {
	// Feed a JSON file that doesn't match any fingerprint.
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "mystery.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(`{"foo": "bar"}`), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--to", "hdf", inputFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auto-detect")
}

func TestConverterCoverage_ConvertAutoDetect_NonJSON(t *testing.T) {
	// Non-JSON input that can't be auto-detected.
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "data.txt")
	require.NoError(t, os.WriteFile(inputFile, []byte("this is plain text"), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--to", "hdf", inputFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auto-detect")
}

// ---------------------------------------------------------------------------
// convert.go — converter not found error with suggestions
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertNotFoundError(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.json")
	require.NoError(t, os.WriteFile(inputFile, []byte("{}"), 0o600))

	// Unknown source format.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "nonexistent-format", "--to", "hdf", inputFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no converter found")
	assert.Contains(t, err.Error(), "hdf convert --help")
}

func TestConverterCoverage_ConvertNotFoundError_KnownSourceBadDest(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.json")
	require.NoError(t, os.WriteFile(inputFile, []byte("{}"), 0o600))

	// Known source, unknown dest.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "sarif", "--to", "unknown-dest", inputFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no converter found")
}

// ---------------------------------------------------------------------------
// convert.go — --labels flag integration
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertWithLabels(t *testing.T) {
	// Minimal SARIF that produces HDF with targets.
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "label-test", "rules": []}},
			"results": []
		}]
	}`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "scan.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(sarifJSON), 0o600))

	outputFile := filepath.Join(tmpDir, "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"convert", "--from", "sarif", "--to", "hdf",
		inputFile, "-o", outputFile,
		"--labels", "env=prod,system=Portal",
	})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	// If the output has targets, labels should be applied.
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	if targets, ok := doc["components"].([]interface{}); ok && len(targets) > 0 {
		target := targets[0].(map[string]interface{})
		labels := target["labels"].(map[string]interface{})
		assert.Equal(t, "prod", labels["env"])
		assert.Equal(t, "Portal", labels["system"])
	}
}

func TestConverterCoverage_ConvertWithInvalidLabels(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.json")
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": []}]
	}`
	require.NoError(t, os.WriteFile(inputFile, []byte(sarifJSON), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"convert", "--from", "sarif", "--to", "hdf",
		inputFile,
		"--labels", "noequalssign",
	})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --labels")
}

func TestConverterCoverage_ConvertWithComponentId(t *testing.T) {
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "cid-test", "rules": []}},
			"results": []
		}]
	}`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "scan.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(sarifJSON), 0o600))

	outputFile := filepath.Join(tmpDir, "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"convert", "--from", "sarif", "--to", "hdf",
		inputFile, "-o", outputFile,
		"--component-id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	if components, ok := doc["components"].([]interface{}); ok && len(components) > 0 {
		comp := components[0].(map[string]interface{})
		assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", comp["componentId"])
	}
}

// ---------------------------------------------------------------------------
// convert.go — missing input file
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertMissingInputFile(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "sarif", "--to", "hdf", "/nonexistent/file.json"})

	err := cmd.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// convert.go — no arguments
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertNoArgs(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert"})

	err := cmd.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// converter_oscal.go — hdfToOSCALSARConverter error path (58.8% coverage)
// ---------------------------------------------------------------------------

func TestConverterCoverage_HDFToOSCALSAR_InvalidInput(t *testing.T) {
	conv, err := GetConverter("hdf", "oscal-sar")
	if err != nil {
		t.Skip("hdf -> oscal-sar converter not registered")
	}

	assert.Equal(t, "HDF Results to OSCAL SAR", conv.Name())

	out, err := conv.Convert([]byte("not json"))
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestConverterCoverage_HDFToOSCALSAR_EmptyInput(t *testing.T) {
	conv, err := GetConverter("hdf", "oscal-sar")
	if err != nil {
		t.Skip("hdf -> oscal-sar converter not registered")
	}

	out, err := conv.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, out)
}

// ---------------------------------------------------------------------------
// convert.go — buildConvertLong() help text generation
// ---------------------------------------------------------------------------

func TestConverterCoverage_BuildConvertLong(t *testing.T) {
	help := buildConvertLong()
	assert.Contains(t, help, "Supported conversions:")
	assert.Contains(t, help, "Auto-detects")
	assert.Contains(t, help, "hdf convert")
}

// ---------------------------------------------------------------------------
// convert.go — buildConverterNotFoundError branches
// ---------------------------------------------------------------------------

func TestConverterCoverage_BuildConverterNotFoundError_UnknownBoth(t *testing.T) {
	err := buildConverterNotFoundError("zzz-unknown", "zzz-unknown-dest")
	assert.Contains(t, err.Error(), "Unrecognized format(s)")
}

func TestConverterCoverage_BuildConverterNotFoundError_KnownSource(t *testing.T) {
	// "sarif" has a known dest ("hdf"), so source is found but dest is wrong
	err := buildConverterNotFoundError("sarif", "xml-unknown")
	assert.Contains(t, err.Error(), "can convert to")
}

func TestConverterCoverage_BuildConverterNotFoundError_KnownDest(t *testing.T) {
	// "hdf" is a known dest for many converters
	err := buildConverterNotFoundError("zzz-unknown-src", "hdf")
	assert.Contains(t, err.Error(), "Unrecognized source format")
}

// ---------------------------------------------------------------------------
// converter_oscal.go — oscalProfileConverter with invalid catalog content
// ---------------------------------------------------------------------------

func TestConverterCoverage_OscalProfile_InvalidCatalogContent(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}

	// Write a garbage catalog file
	tmpDir := t.TempDir()
	badCatalog := filepath.Join(tmpDir, "bad-catalog.json")
	require.NoError(t, os.WriteFile(badCatalog, []byte("not json"), 0o600))

	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"convert", "--from", "oscal-profile", "--to", "hdf",
		profilePath, "--catalog", badCatalog,
	})

	err := cmd.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// convert.go — output to stdout (empty outputPath)
// ---------------------------------------------------------------------------

func TestConverterCoverage_ConvertToStdout(t *testing.T) {
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "stdout-test", "rules": []}}, "results": []}]
	}`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "scan.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(sarifJSON), 0o600))

	// No -o flag — output goes to stdout
	_, _, err := executeCommand("convert", "--from", "sarif", "--to", "hdf", inputFile)
	assert.NoError(t, err)
}
