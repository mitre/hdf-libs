package splunk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func loadEventsFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "splunk-to-hdf", "fixtures", "input", "splunk-events.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read splunk-events.json fixture")
	return data
}

func loadMinimalFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "splunk-to-hdf", "fixtures", "input", "splunk-minimal.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read splunk-minimal.json fixture")
	return data
}

// ---- Structure tests ----

func TestConvertSplunkToHDF_Events(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	assert.NotEmpty(t, result.Baselines, "Baselines should not be empty")

	// The fixture has 1 profile, so we should have 1 baseline
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "disa_stig-el7", baseline.Name)
	assert.Len(t, baseline.Requirements, 6, "Expected 6 controls from events fixture")
}

func TestConvertSplunkToHDF_Minimal(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "disa_stig-el7", baseline.Name)
	require.Len(t, baseline.Requirements, 1, "Minimal fixture has 1 control")
	require.Len(t, baseline.Requirements[0].Results, 1, "Minimal control has 1 result")
}

// ---- Error tests ----

func TestConvertSplunkToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertSplunkToHDF([]byte(""), testConverterVersion)
	assert.Error(t, err, "Should fail on empty input")
}

func TestConvertSplunkToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertSplunkToHDF([]byte("not valid json"), testConverterVersion)
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Contains(t, err.Error(), "invalid Splunk JSON")
}

func TestConvertSplunkToHDF_EmptyArray(t *testing.T) {
	_, err := ConvertSplunkToHDF([]byte("[]"), testConverterVersion)
	assert.Error(t, err, "Should fail on empty array")
	assert.Contains(t, err.Error(), "no Splunk events found in input")
}

func TestConvertSplunkToHDF_NoHeader(t *testing.T) {
	// Craft input with only a control event (no header)
	input := []byte(`[{
		"meta": {"guid": "test-guid", "subtype": "control", "hdf_splunk_schema": "1.0", "filetype": "evaluation", "filename": "test.json", "profile_sha256": "abc123"},
		"id": "V-12345", "title": "Test", "desc": "", "descriptions": {}, "impact": 0.5, "code": "", "tags": {}, "results": [], "refs": []
	}]`)
	_, err := ConvertSplunkToHDF(input, testConverterVersion)
	assert.Error(t, err, "Should fail with no header")
	assert.Contains(t, err.Error(), "expected 1 header event, got 0")
}

// ---- Descriptions test ----

func TestConvertSplunkToHDF_Descriptions(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		require.NotEmpty(t, req.Descriptions, "Requirement %s should have descriptions", req.ID)
		for _, desc := range req.Descriptions {
			assert.NotEmpty(t, desc.Label, "Description label should not be empty for requirement %s", req.ID)
		}
	}

	// Verify specific descriptions are converted from object to array format
	// The fixture controls have "default", "check", and "fix" description keys
	found := false
	for _, req := range baseline.Requirements {
		labels := make(map[string]bool)
		for _, desc := range req.Descriptions {
			labels[desc.Label] = true
		}
		if labels["default"] && labels["check"] && labels["fix"] {
			found = true
			break
		}
	}
	assert.True(t, found, "At least one requirement should have default, check, and fix descriptions")
}

// ---- Tags test ----

func TestConvertSplunkToHDF_Tags(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		require.NotNil(t, req.Tags, "Requirement %s should have tags", req.ID)
	}

	// Find the first control and verify it has NIST tags
	req := baseline.Requirements[0]
	nistTag, hasNist := req.Tags["nist"]
	assert.True(t, hasNist, "Control should have nist tags")
	assert.NotNil(t, nistTag, "NIST tag should not be nil")
}

// ---- Result status test ----

func TestConvertSplunkToHDF_ResultStatus(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	statusCounts := map[hdf.ResultStatus]int{}
	for _, req := range baseline.Requirements {
		for _, res := range req.Results {
			statusCounts[res.Status]++
		}
	}

	// The fixture has 3 passed controls and 3 failed controls
	assert.Greater(t, statusCounts[hdf.Passed], 0, "Should have at least one passed result")
	assert.Greater(t, statusCounts[hdf.Failed], 0, "Should have at least one failed result")
}

// ---- Target test ----

func TestConvertSplunkToHDF_Target(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Targets, "Should have at least one target")
	target := result.Targets[0]
	assert.Equal(t, "centos", target.Name, "Target name should come from platform.name")
	assert.Equal(t, hdf.Host, target.Type, "Target type should be Host")
}

// ---- Impact test ----

func TestConvertSplunkToHDF_Impact(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		// All controls in the fixture have impact 0.5
		assert.Equal(t, 0.5, req.Impact, "Impact should be preserved from control.impact for %s", req.ID)
	}
}

// ---- Source location test ----

func TestConvertSplunkToHDF_SourceLocation(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	found := false
	for _, req := range baseline.Requirements {
		if req.SourceLocation != nil {
			found = true
			assert.NotNil(t, req.SourceLocation.Ref, "SourceLocation.Ref should be set")
			assert.NotNil(t, req.SourceLocation.Line, "SourceLocation.Line should be set")
			break
		}
	}
	assert.True(t, found, "At least one requirement should have a source location")
}

// ---- Generator test ----

func TestConvertSplunkToHDF_Generator(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator, "Generator should not be nil")
	assert.Equal(t, "splunk-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

// ---- Checksum test ----

func TestConvertSplunkToHDF_Checksum(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	require.NotNil(t, baseline.ResultsChecksum, "ResultsChecksum should be present")
	assert.Equal(t, hdf.Sha256, baseline.ResultsChecksum.Algorithm, "Checksum algorithm should be sha256")
	assert.Len(t, baseline.ResultsChecksum.Value, 64, "Checksum value should be 64 hex chars")
}

// ---- Statistics test ----

func TestConvertSplunkToHDF_Statistics(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Statistics, "Statistics should not be nil")
	require.NotNil(t, result.Statistics.Duration, "Duration should not be nil")
	assert.InDelta(t, 10.681, *result.Statistics.Duration, 0.01, "Duration should match header.statistics.duration")
}

// ---- Profile fields test ----

func TestConvertSplunkToHDF_ProfileFields(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	assert.NotNil(t, baseline.Title, "Title should be set")
	assert.Equal(t, "DISA RedHat Enterprise Linux 7 STIG - v1r4", *baseline.Title)
	assert.NotNil(t, baseline.Version, "Version should be set")
	assert.Equal(t, "0.2.0", *baseline.Version)
	assert.NotEmpty(t, baseline.Groups, "Groups should not be empty")
}

// ---- Multiple results per control ----

func TestConvertSplunkToHDF_MultipleResults(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	foundMultiple := false
	for _, req := range baseline.Requirements {
		if len(req.Results) > 1 {
			foundMultiple = true
			break
		}
	}
	assert.True(t, foundMultiple, "At least one control should have multiple results")
}

// ---- JSON round-trip test ----

func TestConvertSplunkToHDF_JSONRoundTrip(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	// Marshal to JSON
	output, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err, "Should marshal to JSON")

	// Verify it's valid JSON by unmarshaling back
	var parsed map[string]interface{}
	err = json.Unmarshal(output, &parsed)
	require.NoError(t, err, "Output should be valid JSON")

	// Verify expected top-level keys
	assert.Contains(t, parsed, "baselines")
	assert.Contains(t, parsed, "targets")
	assert.Contains(t, parsed, "generator")
}
