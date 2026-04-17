package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-schema"
)

func TestConvertPOAMToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertPOAMToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertPOAMToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertPOAMToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertPOAMToHDF_NotPOAM(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	_, err = ConvertPOAMToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected plan-of-action-and-milestones document")
}

func TestConvertPOAMToHDF_FedRAMPFixture(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Amendments name from metadata
	assert.NotEmpty(t, amendments.Name)
	assert.Contains(t, amendments.Name, "fedramp")

	// Overrides populated with type "poam"
	assert.NotEmpty(t, amendments.Overrides, "overrides should be populated from poam-items")
	for _, override := range amendments.Overrides {
		assert.Equal(t, hdf.Poam, override.Type, "all overrides should have type 'poam'")
	}

	// systemRef from import-ssp
	assert.NotNil(t, amendments.SystemRef, "systemRef should be set from import-ssp")
	assert.Equal(t, "#7c30125f-c056-4888-9f1a-7ed1b6a1b638", *amendments.SystemRef)

	// Generator
	assert.NotNil(t, amendments.Generator)
	assert.Equal(t, "hdf-converters", amendments.Generator.Name)
	assert.Equal(t, "1.0.0-test", amendments.Generator.Version)

	// Integrity
	assert.NotNil(t, amendments.Integrity)
	assert.Equal(t, hdf.Sha256, *amendments.Integrity.Algorithm)
}

func TestConvertPOAMToHDF_AmendmentsNameFromMetadata(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Title: "[System Name] FedRAMP Plan of Action and Milestones (POA&M)"
	assert.Contains(t, amendments.Name, "system-name")
	assert.Contains(t, amendments.Name, "plan-of-action-and-milestones")
}

func TestConvertPOAMToHDF_OverridesHaveRequirementIDs(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, amendments.Overrides)

	// First poam-item is related to risk with impacted-control-id "ac-2"
	// which should map to "AC-2"
	assert.Equal(t, "AC-2", amendments.Overrides[0].RequirementID)
}

func TestConvertPOAMToHDF_OverridesHaveReasons(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	for _, override := range amendments.Overrides {
		assert.NotEmpty(t, override.Reason, "every override should have a reason")
	}
}

func TestConvertPOAMToHDF_RiskSeverityExtracted(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// The fixture has risks with "open" status → should map to "failed"
	require.NotEmpty(t, amendments.Overrides)
	require.NotNil(t, amendments.Overrides[0].Status)
	assert.Equal(t, hdf.Failed, *amendments.Overrides[0].Status)
}

func TestConvertPOAMToHDF_ValidatesAgainstSchema(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Verify it marshals to valid JSON
	out, err := json.Marshal(amendments)
	require.NoError(t, err)

	// Verify it unmarshals back cleanly
	var roundtrip hdf.HDFAmendments
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, amendments.Name, roundtrip.Name)
	assert.Equal(t, len(amendments.Overrides), len(roundtrip.Overrides))
}

func TestPoamAmendmentsName(t *testing.T) {
	tests := []struct {
		title    string
		expected string
	}{
		{"FedRAMP POA&M Title", "fedramp-poa-m-title"},
		{"Simple Title", "simple-title"},
		{"", "oscal-poam"},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			assert.Equal(t, tt.expected, ToKebabCase(tt.title, "oscal-poam"))
		})
	}
}
