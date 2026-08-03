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

func TestHDFVersionConverter_LegacyToModern_CLI(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, stderr, err := executeCommand("convert", "--from", "hdf@2", "--to", "hdf@3", fixture)
	require.NoError(t, err, "hdf@2 → hdf@3 should succeed; stderr: %s", stderr)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "baselines", "output should be modern (v3) with baselines")
	assert.Contains(t, result, "components", "output should be modern (v3) with components")
	assert.NotContains(t, result, "profiles", "output should not have legacy profiles")
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
	// --from legacyhdf --to hdf@2 upgrades to modern via legacyhdf, then
	// downgrades to the legacy Heimdall schema (the heimdall2-load target).
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, stderr, err := executeCommand("convert", "--from", "legacyhdf", "--to", "hdf@2", fixture)
	require.NoError(t, err, "legacyhdf → hdf@2 should succeed; stderr: %s", stderr)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "profiles", "output should be legacy (v2) with profiles")
	assert.Contains(t, result, "platform", "output should be legacy (v2) with platform")
	assert.NotContains(t, result, "baselines", "output should not have modern baselines")

	// Should print lossy warning
	assert.Contains(t, stderr, "lossy", "should warn about lossy conversion")
}

func TestHDFVersionConverter_DefaultToVersion(t *testing.T) {
	// --from hdf@2 --to hdf (no version) should default to modern (v3)
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, _, err := executeCommand("convert", "--from", "hdf@2", "--to", "hdf", fixture)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "baselines", "default output should be modern (v3)")
}

func TestHDFVersionConverter_HDFv1_WarnsAndMapsToV2(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	// --from hdf@1: there is no HDF v1 schema; it should warn and be treated as
	// the legacy (v2) shape, then upgrade to modern.
	stdout, stderr, err := executeCommand("convert", "--from", "hdf@1", "--to", "hdf@3", fixture)
	require.NoError(t, err, "hdf@1 should be accepted (mapped to v2); stderr: %s", stderr)
	assert.Contains(t, stderr, "no HDF v1", "should warn that there is no HDF v1")

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "baselines", "hdf@1 input treated as v2, upgraded to modern")

	// --to hdf@1: should warn and produce the legacy (v2) shape.
	stdout, stderr, err = executeCommand("convert", "--from", "legacyhdf", "--to", "hdf@1", fixture)
	require.NoError(t, err, "--to hdf@1 should be accepted (mapped to v2); stderr: %s", stderr)
	assert.Contains(t, stderr, "no HDF v1", "should warn that there is no HDF v1")

	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	assert.Contains(t, result, "profiles", "--to hdf@1 should produce the legacy (v2) shape")
}

func TestHDFVersionConverter_VersionedInterface(t *testing.T) {
	converter, err := GetConverter("hdf", "hdf")
	require.NoError(t, err)

	vc, ok := converter.(VersionedConverter)
	require.True(t, ok, "HDF version converter should implement VersionedConverter")

	versions := vc.SupportedVersions()
	assert.Contains(t, versions, "2")
	assert.Contains(t, versions, "3")
}
