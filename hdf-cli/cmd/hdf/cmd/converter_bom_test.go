package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBOMCopy reads a fixture, prepends a UTF-8 BOM, and writes it to a temp
// file — simulating a Windows-generated (BOM-prefixed) input.
func writeBOMCopy(t *testing.T, srcPath string) string {
	t.Helper()
	content, err := os.ReadFile(srcPath)
	require.NoError(t, err)
	dst := filepath.Join(t.TempDir(), filepath.Base(srcPath))
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, content...)
	require.NoError(t, os.WriteFile(dst, withBOM, 0o600))
	return dst
}

// A leading UTF-8 BOM must not break input handling for any format. These guard
// the chokepoint strip in readInputFile against regression (see hdf-libs-7t7s).

func TestBOM_JSON_AutoDetectConvert(t *testing.T) {
	bomFile := writeBOMCopy(t, converterFixturePath(t, "trufflehog-to-hdf", "input/minimal.json"))
	stdout, stderr, err := executeCommand("convert", bomFile)
	require.NoErrorf(t, err, "BOM-prefixed JSON should auto-detect and convert (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected: TruffleHog")
	assertHDFOutput(t, []byte(stdout))
}

func TestBOM_XML_AutoDetectConvert(t *testing.T) {
	bomFile := writeBOMCopy(t, converterFixturePath(t, "junit-to-hdf", "input/testsuites-mixed.xml"))
	stdout, stderr, err := executeCommand("convert", bomFile)
	require.NoErrorf(t, err, "BOM-prefixed XML should auto-detect and convert (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected:")
	assertHDFOutput(t, []byte(stdout))
}

// CSV is the silent-corruption case: a BOM folds into the first header field, so
// header-name matching fails with no parse error. Explicit --from since CSV is
// excluded from auto-detect by design.
func TestBOM_CSV_ConvertWithExplicitFrom(t *testing.T) {
	bomFile := writeBOMCopy(t, converterFixturePath(t, "prisma-to-hdf", "input/minimal.csv"))
	stdout, stderr, err := executeCommand("convert", "--from", "prisma", bomFile)
	require.NoErrorf(t, err, "BOM-prefixed CSV should convert, not fail on a corrupted first header (stderr: %s)", stderr)
	assertHDFOutput(t, []byte(stdout))
}

func TestBOM_HDF_Validate(t *testing.T) {
	bomFile := writeBOMCopy(t, converterFixturePath(t, "hdf-to-xccdf", "input/minimal.json"))
	_, stderr, err := executeCommand("validate", bomFile)
	require.NoErrorf(t, err, "BOM-prefixed HDF should pass schema validation (stderr: %s)", stderr)
}
