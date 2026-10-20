package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runStandardConverterTests is import-only — every one of its subtests fetches
// GetConverter(source, "hdf") and schema-validates the output as HDF — so an
// exporter's CLI coverage is written out, following converter_hdf_to_csaf_vex_test.go.

func TestHdfToSarifConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "sarif")
	require.NoError(t, err, "hdf -> sarif converter should be registered")
	require.NotNil(t, converter)
	assert.Equal(t, "HDF Results to SARIF", converter.Name())
}

func TestHdfToSarifConverter_ProducesASarifLog(t *testing.T) {
	converter, err := GetConverter("hdf", "sarif")
	require.NoError(t, err)

	output, err := converter.Convert(fixtures.Results.Minimal)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var log struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(output, &log))
	assert.Equal(t, "2.1.0", log.Version)
	assert.Contains(t, log.Schema, "sarif-schema-2.1.0.json")
	assert.Len(t, log.Runs, 1, "one run per baseline")
}

func TestHdfToSarifConverter_RejectsInvalidInput(t *testing.T) {
	converter, err := GetConverter("hdf", "sarif")
	require.NoError(t, err)

	for name, input := range map[string]string{
		"not json": "not json",
		"empty":    "",
	} {
		t.Run(name, func(t *testing.T) {
			output, err := converter.Convert([]byte(input))
			require.Error(t, err)
			assert.Nil(t, output)
			assert.Contains(t, err.Error(), "hdf-to-sarif conversion failed")
		})
	}
}

// End to end through cobra, which is the only path that proves `hdf convert
// --from hdf --to sarif` resolves, writes and skips the HDF output stamping a
// non-HDF target must not get.
func TestHdfToSarifConverter_ConvertCommand(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	outputPath := filepath.Join(dir, "out.sarif")
	require.NoError(t, os.WriteFile(inputPath, fixtures.Results.Minimal, 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "hdf", "--to", "sarif", inputPath, "-o", outputPath})
	require.NoError(t, cmd.Execute())

	written, err := os.ReadFile(outputPath) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(written, &log))
	assert.Equal(t, "2.1.0", log["version"])
}
