package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFVersionConverter_Registered(t *testing.T) {
	converter, err := GetConverter("hdf", "hdf")
	require.NoError(t, err)
	assert.Contains(t, converter.Name(), "HDF")
}

func TestHDFVersionConverter_V1ToV2_CLI(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, stderr, err := executeCommand("convert", "--from", "hdf@1", "--to", "hdf@2", fixture)
	require.NoError(t, err, "hdf@1 → hdf@2 should succeed; stderr: %s", stderr)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "baselines", "output should be v2 with baselines")
	assert.Contains(t, result, "components", "output should be v2 with targets")
	assert.NotContains(t, result, "profiles", "output should not have v1 profiles")
}

func TestHDFVersionConverter_LegacyhdfAlias(t *testing.T) {
	// --from legacyhdf should still work (existing behavior)
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, _, err := executeCommand("convert", "--from", "legacyhdf", "--to", "hdf", fixture)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "baselines")
}

func TestHDFVersionConverter_PostProcessDowngrade(t *testing.T) {
	// --from legacyhdf --to hdf@1 should upgrade to v2 via legacyhdf, then downgrade
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, stderr, err := executeCommand("convert", "--from", "legacyhdf", "--to", "hdf@1", fixture)
	require.NoError(t, err, "legacyhdf → hdf@1 should succeed; stderr: %s", stderr)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "profiles", "output should be v1 with profiles")
	assert.Contains(t, result, "platform", "output should be v1 with platform")
	assert.NotContains(t, result, "baselines", "output should not have v2 baselines")

	// Should print lossy warning
	assert.Contains(t, stderr, "lossy", "should warn about lossy conversion")
}

func TestHDFVersionConverter_DefaultToVersion(t *testing.T) {
	// --from hdf@1 --to hdf (no version) should default to v2
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, _, err := executeCommand("convert", "--from", "hdf@1", "--to", "hdf", fixture)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "baselines", "default output should be v2")
}

func TestHDFVersionConverter_VersionedInterface(t *testing.T) {
	converter, err := GetConverter("hdf", "hdf")
	require.NoError(t, err)

	vc, ok := converter.(VersionedConverter)
	require.True(t, ok, "HDF version converter should implement VersionedConverter")

	versions := vc.SupportedVersions()
	assert.Contains(t, versions, "1")
	assert.Contains(t, versions, "2")
}
