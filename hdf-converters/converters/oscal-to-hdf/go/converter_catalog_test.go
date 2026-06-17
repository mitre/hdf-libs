package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func TestConvertCatalogToHDF_FullCatalog(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-800-53-rev5.json")
	require.NoError(t, err)

	baseline, err := ConvertCatalogToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Basic structure
	assert.NotEmpty(t, baseline.Name)
	assert.NotNil(t, baseline.Title)
	assert.Contains(t, *baseline.Title, "800-53")
	assert.NotNil(t, baseline.Version)
	assert.Equal(t, "5.2.0", *baseline.Version)

	// 20 control families → 20 groups
	assert.Len(t, baseline.Groups, 20)
	assert.Equal(t, "ac", baseline.Groups[0].ID)
	assert.Equal(t, "Access Control", *baseline.Groups[0].Title)

	// Full catalog: 1196 controls+enhancements
	assert.Greater(t, len(baseline.Requirements), 1000)

	// Generator
	assert.NotNil(t, baseline.Generator)
	assert.Equal(t, "oscal-catalog-to-hdf", baseline.Generator.Name)
	assert.Equal(t, "1.0.0-test", baseline.Generator.Version)

	// Integrity
	assert.NotNil(t, baseline.Integrity)
	assert.Equal(t, hdf.Sha256, *baseline.Integrity.Algorithm)

	// Status
	assert.NotNil(t, baseline.Status)
	assert.Equal(t, "loaded", *baseline.Status)
}

func TestConvertCatalogToHDF_ResolvedCatalog(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	baseline, err := ConvertCatalogToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Moderate baseline: 177 controls + 110 enhancements = 287 total
	assert.Equal(t, 287, len(baseline.Requirements))

	// Verify AC-1 exists and has correct fields
	var ac1 *hdf.BaselineRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "AC-1" {
			ac1 = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, ac1, "AC-1 should exist in moderate baseline")
	assert.NotNil(t, ac1.Title)
	assert.Equal(t, "Policy and Procedures", *ac1.Title)
	assert.Equal(t, 0.5, ac1.Impact) // default for catalog controls

	// Should have at least a default description
	assert.GreaterOrEqual(t, len(ac1.Descriptions), 1)
	assert.Equal(t, "default", ac1.Descriptions[0].Label)
	assert.NotEmpty(t, ac1.Descriptions[0].Data)

	// Tags should include NIST tag
	nist, ok := ac1.Tags["nist"]
	assert.True(t, ok)
	assert.Equal(t, []string{"AC-1"}, nist)
}

func TestConvertCatalogToHDF_ControlEnhancements(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	baseline, err := ConvertCatalogToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// AC-2 (1) is an enhancement of AC-2
	var ac21 *hdf.BaselineRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "AC-2 (1)" {
			ac21 = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, ac21, "AC-2 (1) should exist")
	assert.NotNil(t, ac21.Title)
}

func TestConvertCatalogToHDF_Descriptions(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	baseline, err := ConvertCatalogToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// AC-1 should have statement, guidance, and assessment-objective
	var ac1 *hdf.BaselineRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "AC-1" {
			ac1 = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, ac1)

	labels := make(map[string]bool)
	for _, d := range ac1.Descriptions {
		labels[d.Label] = true
	}
	assert.True(t, labels["default"], "should have default description (from statement)")
	assert.True(t, labels["rationale"], "should have rationale (from guidance)")
	assert.True(t, labels["check"], "should have check (from assessment-objective)")
}

func TestConvertCatalogToHDF_Groups(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	baseline, err := ConvertCatalogToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Check that groups reference valid requirement IDs
	reqIDs := make(map[string]bool)
	for _, r := range baseline.Requirements {
		reqIDs[r.ID] = true
	}

	for _, g := range baseline.Groups {
		for _, rid := range g.Requirements {
			assert.True(t, reqIDs[rid], "group %s references non-existent requirement %s", g.ID, rid)
		}
	}
}

func TestConvertCatalogToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertCatalogToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertCatalogToHDF_NotCatalog(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/profile-moderate.json")
	require.NoError(t, err)

	_, err = ConvertCatalogToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected catalog document")
}

func TestConvertCatalogToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertCatalogToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertCatalogToHDF_ValidatesAgainstSchema(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	baseline, err := ConvertCatalogToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Verify it marshals to valid JSON
	out, err := json.Marshal(baseline)
	require.NoError(t, err)

	// Verify it unmarshals back cleanly
	var roundtrip hdf.HDFBaseline
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, baseline.Name, roundtrip.Name)
	assert.Equal(t, len(baseline.Requirements), len(roundtrip.Requirements))
}

func TestCatalogBaselineName(t *testing.T) {
	tests := []struct {
		title    string
		expected string
	}{
		{"NIST SP 800-53 Rev 5", "nist-sp-800-53-rev-5"},
		{"Simple Title", "simple-title"},
		{"", "oscal-catalog"},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			assert.Equal(t, tt.expected, ToKebabCase(tt.title, "oscal-catalog"))
		})
	}
}
