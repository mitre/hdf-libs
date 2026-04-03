package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSarifConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "sarif",
		DisplayName:    "SARIF to HDF",
		FixtureDir:     "sarif-to-hdf",
		MinimalFixture: "input/sarif_input.sarif",
		ErrPrefix:      "sarif conversion failed",
	})
}

func TestSarifConverter_Convert_InvalidStructure(t *testing.T) {
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(`{"not": "sarif"}`))
	assert.Error(t, err, "Should fail on invalid SARIF structure")
	assert.Nil(t, output)
}

func TestSarifConverter_VersionedConverter(t *testing.T) {
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err)

	vc, ok := converter.(VersionedConverter)
	require.True(t, ok, "SARIF converter should implement VersionedConverter")

	t.Run("SupportedVersions returns versions latest first", func(t *testing.T) {
		versions := vc.SupportedVersions()
		require.NotEmpty(t, versions)
		assert.Equal(t, "2.1.0", versions[0], "latest version should be first")
		assert.Contains(t, versions, "2.0.0")
	})

	t.Run("SetInputVersion does not error", func(t *testing.T) {
		// Should not panic or error for known versions
		vc.SetInputVersion("2.1.0")
		vc.SetInputVersion("2.0.0")
		// Empty string means "use latest" — should also be safe
		vc.SetInputVersion("")
	})
}

func TestSarifConverter_VersionPassthrough_CLI(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "sarif-to-hdf", "fixtures")
	fixturePath := filepath.Join(fixtureDir, "input", "sarif_input.sarif")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("SARIF fixture not available")
	}

	t.Run("--from sarif@2.1 works", func(t *testing.T) {
		stdout, _, err := executeCommand("convert", "--from", "sarif@2.1.0", "--to", "hdf", fixturePath)
		require.NoError(t, err, "sarif@2.1.0 should parse and convert")
		var result map[string]any
		require.NoError(t, json.Unmarshal([]byte(stdout), &result))
		assert.Contains(t, result, "baselines")
	})

	t.Run("--from sarif (no version) still works", func(t *testing.T) {
		stdout, _, err := executeCommand("convert", "--from", "sarif", "--to", "hdf", fixturePath)
		require.NoError(t, err, "sarif without version should still work")
		var result map[string]any
		require.NoError(t, json.Unmarshal([]byte(stdout), &result))
		assert.Contains(t, result, "baselines")
	})
}
