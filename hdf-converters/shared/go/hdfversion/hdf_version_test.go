package hdfversion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func convertersDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "converters")
}

func legacyhdfFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(convertersDir(), "legacyhdf-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// Version identifiers: v2 = legacy Heimdall schema (profiles/platform),
// v3 = modern hdf-libs schema (baselines/components). There is no HDF v1
// transform (v1 = raw InSpec; see NormalizeVersion).

func TestTransformHDF_LegacyToModern(t *testing.T) {
	legacyInput := legacyhdfFixture(t, "minimal.json")

	output, err := TransformHDF(legacyInput, LegacyVersion, ModernVersion)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	// Output should be valid JSON with modern (v3) structure.
	var modern map[string]any
	require.NoError(t, json.Unmarshal(output, &modern))
	assert.Contains(t, modern, "baselines", "modern output should have baselines")
	assert.Contains(t, modern, "components", "modern output should have components")
	// Should NOT have legacy fields.
	assert.NotContains(t, modern, "profiles", "modern output should not have profiles")
	assert.NotContains(t, modern, "platform", "modern output should not have platform")
}

func TestTransformHDF_ModernToLegacy(t *testing.T) {
	// First get a modern document by upgrading a legacy one.
	legacyInput := legacyhdfFixture(t, "minimal.json")
	modernOutput, err := TransformHDF(legacyInput, LegacyVersion, ModernVersion)
	require.NoError(t, err)

	// Now downgrade back to the legacy shape.
	legacyOutput, err := TransformHDF(modernOutput, ModernVersion, LegacyVersion)
	require.NoError(t, err)
	require.NotEmpty(t, legacyOutput)

	// Output should have legacy (v2) structure.
	var legacy map[string]any
	require.NoError(t, json.Unmarshal(legacyOutput, &legacy))
	assert.Contains(t, legacy, "profiles", "legacy output should have profiles")
	assert.Contains(t, legacy, "platform", "legacy output should have platform")
	assert.Contains(t, legacy, "statistics", "legacy output should have statistics")
	// Should NOT have modern fields.
	assert.NotContains(t, legacy, "baselines", "legacy output should not have baselines")
	assert.NotContains(t, legacy, "components", "legacy output should not have components")
}

func TestTransformHDF_SameVersion(t *testing.T) {
	legacyInput := legacyhdfFixture(t, "minimal.json")

	// Same version should return input unchanged.
	output, err := TransformHDF(legacyInput, LegacyVersion, LegacyVersion)
	require.NoError(t, err)
	assert.JSONEq(t, string(legacyInput), string(output))
}

func TestTransformHDF_UnknownTransform(t *testing.T) {
	// "1" is not a transform key — raw InSpec is not a distinct schema version.
	_, err := TransformHDF([]byte(`{}`), "1", ModernVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no HDF transform")
}

func TestTransformHDF_InvalidJSON(t *testing.T) {
	_, err := TransformHDF([]byte(`not json`), LegacyVersion, ModernVersion)
	require.Error(t, err)
}

func TestTransformHDF_RoundTrip(t *testing.T) {
	legacyInput := legacyhdfFixture(t, "minimal.json")

	// legacy → modern → legacy should preserve core fields.
	modern, err := TransformHDF(legacyInput, LegacyVersion, ModernVersion)
	require.NoError(t, err)

	legacyAgain, err := TransformHDF(modern, ModernVersion, LegacyVersion)
	require.NoError(t, err)

	var original map[string]any
	var roundTripped map[string]any
	require.NoError(t, json.Unmarshal(legacyInput, &original))
	require.NoError(t, json.Unmarshal(legacyAgain, &roundTripped))

	origProfiles, _ := original["profiles"].([]any)
	rtProfiles, _ := roundTripped["profiles"].([]any)
	assert.Equal(t, len(origProfiles), len(rtProfiles), "profile count should survive round-trip")
}

func TestDetectHDFVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"legacy (v2) with profiles+platform", `{"version":"3.4.5","profiles":[],"platform":{"name":"test"}}`, LegacyVersion, false},
		{"modern (v3) with baselines+components", `{"baselines":[],"components":[]}`, ModernVersion, false},
		{"ambiguous", `{"version":"1.0"}`, "", true},
		{"invalid json", `not json`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectHDFVersion([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	// "1" has no distinct schema → maps to legacy (v2) with a warning.
	got, warn := NormalizeVersion("1")
	assert.Equal(t, LegacyVersion, got)
	assert.NotEmpty(t, warn, "hdf@1 should warn")

	// "2", "3", and "" pass through with no warning.
	for _, v := range []string{LegacyVersion, ModernVersion, ""} {
		got, warn := NormalizeVersion(v)
		assert.Equal(t, v, got)
		assert.Empty(t, warn, "hdf@%s should not warn", v)
	}
}
