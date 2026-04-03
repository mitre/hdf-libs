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

func TestTransformHDF_V1ToV2(t *testing.T) {
	v1Input := legacyhdfFixture(t, "minimal.json")

	output, err := TransformHDF(v1Input, "1", "2")
	require.NoError(t, err)
	require.NotEmpty(t, output)

	// Output should be valid JSON with v2 structure (baselines, components)
	var v2 map[string]any
	require.NoError(t, json.Unmarshal(output, &v2))
	assert.Contains(t, v2, "baselines", "v2 output should have baselines")
	assert.Contains(t, v2, "components", "v2 output should have components")
	// Should NOT have v1 fields
	assert.NotContains(t, v2, "profiles", "v2 output should not have profiles")
	assert.NotContains(t, v2, "platform", "v2 output should not have platform")
}

func TestTransformHDF_V2ToV1(t *testing.T) {
	// First get a v2 document by upgrading a v1
	v1Input := legacyhdfFixture(t, "minimal.json")
	v2Output, err := TransformHDF(v1Input, "1", "2")
	require.NoError(t, err)

	// Now downgrade back to v1
	v1Output, err := TransformHDF(v2Output, "2", "1")
	require.NoError(t, err)
	require.NotEmpty(t, v1Output)

	// Output should have v1 structure (profiles, platform)
	var v1 map[string]any
	require.NoError(t, json.Unmarshal(v1Output, &v1))
	assert.Contains(t, v1, "profiles", "v1 output should have profiles")
	assert.Contains(t, v1, "platform", "v1 output should have platform")
	assert.Contains(t, v1, "statistics", "v1 output should have statistics")
	// Should NOT have v2 fields
	assert.NotContains(t, v1, "baselines", "v1 output should not have baselines")
	assert.NotContains(t, v1, "components", "v1 output should not have components")
}

func TestTransformHDF_SameVersion(t *testing.T) {
	v1Input := legacyhdfFixture(t, "minimal.json")

	// Same version should return input unchanged
	output, err := TransformHDF(v1Input, "1", "1")
	require.NoError(t, err)
	assert.JSONEq(t, string(v1Input), string(output))
}

func TestTransformHDF_UnknownTransform(t *testing.T) {
	_, err := TransformHDF([]byte(`{}`), "3", "2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no HDF transform")
}

func TestTransformHDF_InvalidJSON(t *testing.T) {
	_, err := TransformHDF([]byte(`not json`), "1", "2")
	require.Error(t, err)
}

func TestTransformHDF_RoundTrip(t *testing.T) {
	v1Input := legacyhdfFixture(t, "minimal.json")

	// v1 → v2 → v1 should preserve core fields
	v2, err := TransformHDF(v1Input, "1", "2")
	require.NoError(t, err)

	v1Again, err := TransformHDF(v2, "2", "1")
	require.NoError(t, err)

	// Parse both for comparison
	var original map[string]any
	var roundTripped map[string]any
	require.NoError(t, json.Unmarshal(v1Input, &original))
	require.NoError(t, json.Unmarshal(v1Again, &roundTripped))

	// Core structural fields should survive round-trip
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
		{"v1 with profiles+platform", `{"version":"3.4.5","profiles":[],"platform":{"name":"test"}}`, "1", false},
		{"v2 with baselines+components", `{"baselines":[],"components":[]}`, "2", false},
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
