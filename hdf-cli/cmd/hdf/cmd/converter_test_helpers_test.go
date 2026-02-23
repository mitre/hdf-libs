package cmd

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	validators "github.com/mitre/hdf-validators/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// converterFixturePath returns the absolute path to a fixture file for a named converter.
// converterDirName is the directory name under hdf-converters/converters/ (e.g. "sarif-to-hdf").
// The test is skipped if the fixture file does not exist.
func converterFixturePath(t *testing.T, converterDirName, name string) string {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), converterDirName, "fixtures", name)
	path = filepath.Clean(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Fixture not found: %s", path)
	}
	return path
}

// assertHDFOutput validates converter output against the HDF JSON Schema.
// This ensures converters produce structurally valid HDF, not just JSON
// containing the right field names.
func assertHDFOutput(t *testing.T, output []byte) {
	t.Helper()
	require.NotEmpty(t, output, "Converter output should not be empty")

	result := validators.ValidateResults(output)
	assert.True(t, result.Valid,
		"Converter output must pass HDF schema validation: %s", result.Error())
}
