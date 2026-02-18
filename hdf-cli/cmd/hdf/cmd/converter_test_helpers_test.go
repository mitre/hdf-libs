package cmd

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/stretchr/testify/assert"
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

// assertHDFOutput verifies that output bytes contain the expected top-level HDF JSON structure fields.
func assertHDFOutput(t *testing.T, output []byte) {
	t.Helper()
	s := string(output)
	assert.Contains(t, s, "\"baselines\"")
	assert.Contains(t, s, "\"generator\"")
	assert.Contains(t, s, "\"timestamp\"")
}
