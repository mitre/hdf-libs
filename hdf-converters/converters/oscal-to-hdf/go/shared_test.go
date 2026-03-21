package oscal

import (
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlIDToNistTag(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ac-1", "AC-1"},
		{"ac-2.3", "AC-2 (3)"},
		{"si-7.1", "SI-7 (1)"},
		{"ra-5.11", "RA-5 (11)"},
		{"cm-2", "CM-2"},
		{"AC-1", "AC-1"}, // already uppercase
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ControlIDToNistTag(tt.input))
		})
	}
}

func TestControlIDsToNistTags(t *testing.T) {
	tags := ControlIDsToNistTags([]string{"ac-1", "ac-2.3", "ac-1"})
	assert.Equal(t, []string{"AC-1", "AC-2 (3)"}, tags)
}

func TestControlIDsToNistTags_Empty(t *testing.T) {
	tags := ControlIDsToNistTags(nil)
	assert.Empty(t, tags)
}

func TestExtractControlIDFromObjectiveID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ac-1.a.1_obj.1", "ac-1"},
		{"ac-2.3.a_obj.1", "ac-2.3"},
		{"si-7_obj.1", "si-7"},
		{"plain-id", "plain-id"},
		{"ac-1", "ac-1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractControlIDFromObjectiveID(tt.input))
		})
	}
}

func TestOscalStatusToHDF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		{"satisfied", "passed", true},
		{"not-satisfied", "failed", true},
		{"closed", "passed", true},
		{"open", "failed", true},
		{"Satisfied", "passed", true}, // case-insensitive
		{" open ", "failed", true},    // trimmed
		{"unknown", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			status, ok := OscalStatusToHDF(tt.input)
			assert.Equal(t, tt.expected, status)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestExtractPropValue(t *testing.T) {
	props := []Property{
		{Name: "label", Value: "AC-1"},
		{Name: "sort-id", Value: "ac-01"},
		{Name: "status", Value: "withdrawn", Ns: "https://fedramp.gov/ns"},
	}

	val, ok := ExtractPropValue(props, "label", "")
	assert.True(t, ok)
	assert.Equal(t, "AC-1", val)

	val, ok = ExtractPropValue(props, "status", "https://fedramp.gov/ns")
	assert.True(t, ok)
	assert.Equal(t, "withdrawn", val)

	_, ok = ExtractPropValue(props, "status", "wrong-ns")
	assert.False(t, ok)

	_, ok = ExtractPropValue(props, "missing", "")
	assert.False(t, ok)
}

func TestExtractAllPropValues(t *testing.T) {
	props := []Property{
		{Name: "tag", Value: "a"},
		{Name: "other", Value: "x"},
		{Name: "tag", Value: "b"},
	}
	assert.Equal(t, []string{"a", "b"}, ExtractAllPropValues(props, "tag", ""))
	assert.Nil(t, ExtractAllPropValues(props, "missing", ""))
}

func TestFlattenParts(t *testing.T) {
	parts := []Part{
		{
			Name:  "statement",
			Prose: "Top level statement.",
			Parts: []Part{
				{Name: "item", Prose: "Sub-item a."},
				{Name: "item", Prose: "Sub-item b.", Parts: []Part{
					{Name: "item", Prose: "Nested c."},
				}},
			},
		},
	}

	result := FlattenParts(parts)
	assert.Contains(t, result, "Top level statement.")
	assert.Contains(t, result, "Sub-item a.")
	assert.Contains(t, result, "Sub-item b.")
	assert.Contains(t, result, "Nested c.")
}

func TestFlattenParts_Empty(t *testing.T) {
	assert.Equal(t, "", FlattenParts(nil))
	assert.Equal(t, "", FlattenParts([]Part{}))
}

func TestFlattenPartsByName(t *testing.T) {
	parts := []Part{
		{Name: "statement", Prose: "The org shall..."},
		{Name: "guidance", Prose: "Guidance text here."},
		{Name: "statement", Prose: "Second statement."},
	}

	result := FlattenPartsByName(parts, "statement")
	assert.Contains(t, result, "The org shall...")
	assert.Contains(t, result, "Second statement.")
	assert.NotContains(t, result, "Guidance")
}

func TestExtractRiskSeverity(t *testing.T) {
	chars := []Characterization{
		{
			Facets: []Facet{
				{Name: "impact", Value: "high"},
			},
		},
	}
	assert.Equal(t, 0.7, ExtractRiskSeverity(chars, 0.5))

	chars[0].Facets[0].Value = "critical"
	assert.Equal(t, 0.9, ExtractRiskSeverity(chars, 0.5))

	chars[0].Facets[0].Value = "moderate"
	assert.Equal(t, 0.5, ExtractRiskSeverity(chars, 0.5))

	chars[0].Facets[0].Value = "low"
	assert.Equal(t, 0.3, ExtractRiskSeverity(chars, 0.5))

	// Unknown value → default
	chars[0].Facets[0].Value = "bizarre"
	assert.Equal(t, 0.5, ExtractRiskSeverity(chars, 0.5))

	// Empty characterizations → default
	assert.Equal(t, 0.5, ExtractRiskSeverity(nil, 0.5))
}

func TestExtractMetadata(t *testing.T) {
	m := Metadata{
		Title:        "Test Catalog",
		Version:      "5.2.0",
		OscalVersion: "1.1.3",
		LastModified: "2025-08-26T15:10:16Z",
	}
	info := ExtractMetadata(m)
	assert.Equal(t, "Test Catalog", info.Title)
	assert.Equal(t, "5.2.0", info.Version)
	assert.Equal(t, "1.1.3", info.OscalVersion)
	assert.Equal(t, "2025-08-26T15:10:16Z", info.LastModified)
}

func TestToKebabCase(t *testing.T) {
	tests := []struct {
		title    string
		fallback string
		expected string
	}{
		{"NIST SP 800-53 Rev 5", "oscal-catalog", "nist-sp-800-53-rev-5"},
		{"My Component!!", "oscal-component", "my-component"},
		{"", "oscal-catalog", "oscal-catalog"},
		{"simple", "fallback", "simple"},
		{strings.Repeat("a", 100), "fallback", strings.Repeat("a", 80)},
		{"---leading---trailing---", "fallback", "leading-trailing"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, ToKebabCase(tt.title, tt.fallback))
		})
	}
}

func TestNistTagToControlID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AC-1", "ac-1"},
		{"AC-2 (3)", "ac-2.3"},
		{"SI-7 (1)", "si-7.1"},
		{"  AC-1 ", "ac-1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, NistTagToControlID(tt.input))
		})
	}
}

func TestParseOscalDocument(t *testing.T) {
	t.Run("valid catalog", func(t *testing.T) {
		input := `{"catalog":{"uuid":"test","metadata":{"title":"Test","version":"1.0","oscal-version":"1.1.2","last-modified":"2025-01-01T00:00:00Z"}}}`
		doc, err := ParseOscalDocument([]byte(input), "catalog", "test")
		require.NoError(t, err)
		assert.NotNil(t, doc.Catalog)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParseOscalDocument(nil, "catalog", "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty input")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParseOscalDocument([]byte("not json"), "catalog", "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JSON")
	})

	t.Run("wrong document type", func(t *testing.T) {
		input := `{"profile":{"uuid":"test","metadata":{"title":"Test","version":"1.0","oscal-version":"1.1.2","last-modified":"2025-01-01T00:00:00Z"}}}`
		_, err := ParseOscalDocument([]byte(input), "catalog", "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected catalog document, got profile")
	})
}

func TestGenerateUUID(t *testing.T) {
	uuid := GenerateUUID()
	assert.Len(t, uuid, 36) // standard UUID length with dashes
	// version 4 indicator at position 14
	assert.Equal(t, byte('4'), uuid[14])

	// Two UUIDs should be different
	uuid2 := GenerateUUID()
	assert.NotEqual(t, uuid, uuid2)
}

func TestImpactToSeverity(t *testing.T) {
	tests := []struct {
		impact   float64
		expected string
	}{
		{0.9, "critical"},
		{1.0, "critical"},
		{0.7, "high"},
		{0.8, "high"},
		{0.5, "moderate"},
		{0.4, "moderate"},
		{0.3, "low"},
		{0.1, "low"},
		{0.0, "info"},
		{0.05, "info"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, ImpactToSeverity(tt.impact))
	}
}

func TestHDFStatusToOSCALRiskStatus(t *testing.T) {
	assert.Equal(t, "closed", HDFStatusToOSCALRiskStatus(hdf.Passed))
	assert.Equal(t, "closed", HDFStatusToOSCALRiskStatus(hdf.NotApplicable))
	assert.Equal(t, "open", HDFStatusToOSCALRiskStatus(hdf.Failed))
	assert.Equal(t, "open", HDFStatusToOSCALRiskStatus(hdf.Error))
	assert.Equal(t, "open", HDFStatusToOSCALRiskStatus(hdf.NotReviewed))
}

func TestOscalVersion(t *testing.T) {
	assert.Equal(t, "1.1.2", OscalVersion)
}
