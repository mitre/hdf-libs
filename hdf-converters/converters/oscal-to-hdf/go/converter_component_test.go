package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func TestConvertComponentDefinitionToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertComponentDefinitionToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertComponentDefinitionToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertComponentDefinitionToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertComponentDefinitionToHDF_NotComponentDef(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	_, err = ConvertComponentDefinitionToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected component-definition document")
}

func TestConvertComponentDefinitionToHDF_NoComponents(t *testing.T) {
	input := []byte(`{"component-definition":{"uuid":"abc","metadata":{"title":"Empty","last-modified":"2024-01-01","version":"1.0","oscal-version":"1.1.2"},"components":[]}}`)
	_, err := ConvertComponentDefinitionToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no components")
}

func TestConvertComponentDefinitionToHDF_Fixture(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/component-example.json")
	require.NoError(t, err)

	baseline, err := ConvertComponentDefinitionToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Basic structure
	assert.NotEmpty(t, baseline.Name)
	assert.Equal(t, "test-component-1", baseline.Name)
	assert.NotNil(t, baseline.Title)
	assert.Equal(t, "Test Component Definition", *baseline.Title)
	assert.NotNil(t, baseline.Version)
	assert.Equal(t, "20231012", *baseline.Version)

	// Status
	assert.NotNil(t, baseline.Status)
	assert.Equal(t, "loaded", *baseline.Status)

	// Generator
	assert.NotNil(t, baseline.Generator)
	assert.Equal(t, "hdf-converters", baseline.Generator.Name)
	assert.Equal(t, "1.0.0-test", baseline.Generator.Version)

	// Integrity
	assert.NotNil(t, baseline.Integrity)
	assert.Equal(t, hdf.Sha256, *baseline.Integrity.Algorithm)

	// Requirements: fixture has 2 control-implementations, each with 1 implemented-requirement
	// Both reference ac-2.3 but from different sources
	assert.Len(t, baseline.Requirements, 2)
}

func TestConvertComponentDefinitionToHDF_RequirementIDs(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/component-example.json")
	require.NoError(t, err)

	baseline, err := ConvertComponentDefinitionToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Both requirements should have NIST notation ID
	for _, req := range baseline.Requirements {
		assert.Equal(t, "AC-2 (3)", req.ID)
		assert.NotNil(t, req.Title)
		assert.Equal(t, "AC-2 (3)", *req.Title)
	}
}

func TestConvertComponentDefinitionToHDF_Descriptions(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/component-example.json")
	require.NoError(t, err)

	baseline, err := ConvertComponentDefinitionToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, baseline.Requirements)
	req := baseline.Requirements[0]

	// Should have at least a default description
	assert.GreaterOrEqual(t, len(req.Descriptions), 1)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.NotEmpty(t, req.Descriptions[0].Data)
	assert.Contains(t, req.Descriptions[0].Data, "Inactive accounts")
}

func TestConvertComponentDefinitionToHDF_Tags(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/component-example.json")
	require.NoError(t, err)

	baseline, err := ConvertComponentDefinitionToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, baseline.Requirements)
	req := baseline.Requirements[0]

	nist, ok := req.Tags["nist"]
	assert.True(t, ok)
	assert.Equal(t, []string{"AC-2 (3)"}, nist)
}

func TestConvertComponentDefinitionToHDF_Impact(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/component-example.json")
	require.NoError(t, err)

	baseline, err := ConvertComponentDefinitionToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, baseline.Requirements)
	for _, req := range baseline.Requirements {
		assert.Equal(t, 0.5, req.Impact)
	}
}

func TestConvertComponentDefinitionToHDF_RoundTrip(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/component-example.json")
	require.NoError(t, err)

	baseline, err := ConvertComponentDefinitionToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	out, err := json.Marshal(baseline)
	require.NoError(t, err)

	var roundtrip hdf.HDFBaseline
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, baseline.Name, roundtrip.Name)
	assert.Equal(t, len(baseline.Requirements), len(roundtrip.Requirements))
}

func TestComponentBaselineName(t *testing.T) {
	tests := []struct {
		compTitle string
		metaTitle string
		expected  string
	}{
		{"My Component", "My Def", "my-component"},
		{"", "Component Def Title", "component-def-title"},
		{"", "", "oscal-component-definition"},
	}
	for _, tt := range tests {
		t.Run(tt.compTitle+"/"+tt.metaTitle, func(t *testing.T) {
			name := tt.compTitle
			if name == "" {
				name = tt.metaTitle
			}
			assert.Equal(t, tt.expected, ToKebabCase(name, "oscal-component-definition"))
		})
	}
}
