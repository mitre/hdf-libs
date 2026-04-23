package cmd

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	validators "github.com/mitre/hdf-libs/hdf-validators/go"
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

// converterTestCase defines a standard set of tests for a CLI converter wrapper.
// Every converter that registers via registerHDFConverter should have these tests.
type converterTestCase struct {
	// Source is the converter's registered source format name (e.g., "gosec").
	Source string
	// DisplayName is the expected return value of Converter.Name() (e.g., "gosec to HDF").
	DisplayName string
	// FixtureDir is the directory under hdf-converters/converters/ (e.g., "gosec-to-hdf").
	FixtureDir string
	// MinimalFixture is the path relative to fixtures/ (e.g., "input/minimal.json").
	MinimalFixture string
	// ErrPrefix is the expected substring in error messages (e.g., "gosec conversion failed").
	ErrPrefix string
	// InvalidInput is the input bytes used for the invalid-input test.
	// Defaults to "not valid json" if empty.
	InvalidInput string
}

// runStandardConverterTests runs the 4 standard tests that every converter must pass:
// IsRegistered, Convert_Minimal, Convert_InvalidInput, Convert_EmptyInput.
func runStandardConverterTests(t *testing.T, tc converterTestCase) {
	t.Helper()

	invalidInput := tc.InvalidInput
	if invalidInput == "" {
		invalidInput = "not valid json"
	}

	t.Run("IsRegistered", func(t *testing.T) {
		converter, err := GetConverter(tc.Source, "hdf")
		require.NoError(t, err, "%s converter should be registered", tc.Source)
		assert.NotNil(t, converter)
		assert.Equal(t, tc.DisplayName, converter.Name())
	})

	t.Run("Convert_Minimal", func(t *testing.T) {
		inputData, err := os.ReadFile(converterFixturePath(t, tc.FixtureDir, tc.MinimalFixture))
		require.NoError(t, err, "failed to read %s fixture", tc.MinimalFixture)

		converter, err := GetConverter(tc.Source, "hdf")
		require.NoError(t, err)

		output, err := converter.Convert(inputData)
		require.NoError(t, err, "conversion should succeed")
		require.NotEmpty(t, output)

		assertHDFOutput(t, output)
	})

	t.Run("Convert_InvalidInput", func(t *testing.T) {
		converter, err := GetConverter(tc.Source, "hdf")
		require.NoError(t, err)

		output, err := converter.Convert([]byte(invalidInput))
		assert.Error(t, err)
		assert.Nil(t, output)
		assert.Contains(t, err.Error(), tc.ErrPrefix)
	})

	t.Run("Convert_EmptyInput", func(t *testing.T) {
		converter, err := GetConverter(tc.Source, "hdf")
		require.NoError(t, err)

		output, err := converter.Convert([]byte(""))
		assert.Error(t, err)
		assert.Nil(t, output)
	})
}
