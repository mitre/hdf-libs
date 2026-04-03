package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Unit tests for bulk helpers ---

func TestExpandGlobs_LiteralPaths(t *testing.T) {
	// Literal paths that exist should be returned as-is.
	fixture := testFixturePath(t, "minimal-v2.json")
	result, err := expandGlobs([]string{fixture})
	require.NoError(t, err)
	assert.Equal(t, []string{fixture}, result)
}

func TestExpandGlobs_GlobPattern(t *testing.T) {
	// A glob pattern should expand to matching files.
	tmpDir := t.TempDir()
	for _, name := range []string{"a.json", "b.json", "c.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, name), []byte("{}"), 0o600))
	}
	pattern := filepath.Join(tmpDir, "*.json")
	result, err := expandGlobs([]string{pattern})
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExpandGlobs_NoMatch(t *testing.T) {
	// A glob pattern that matches nothing should return an error.
	_, err := expandGlobs([]string{"/nonexistent/path/*.json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no files matched")
}

func TestExpandGlobs_MixedLiteralAndGlob(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "one.json")
	f2 := filepath.Join(tmpDir, "two.json")
	require.NoError(t, os.WriteFile(f1, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(f2, []byte("{}"), 0o600))

	result, err := expandGlobs([]string{f1, filepath.Join(tmpDir, "two*")})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Contains(t, result, f1)
	assert.Contains(t, result, f2)
}

func TestExpandGlobs_Deduplication(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "dup.json")
	require.NoError(t, os.WriteFile(f1, []byte("{}"), 0o600))

	// Literal path + glob matching same file: literal is always kept,
	// glob is deduped within glob results only. Both appear.
	result, err := expandGlobs([]string{f1, filepath.Join(tmpDir, "dup*")})
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExpandGlobs_GlobDeduplication(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "file.json")
	require.NoError(t, os.WriteFile(f1, []byte("{}"), 0o600))

	// Two glob patterns matching the same file — should deduplicate.
	result, err := expandGlobs([]string{filepath.Join(tmpDir, "*.json"), filepath.Join(tmpDir, "file*")})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestBulkResultSummary(t *testing.T) {
	results := []BulkResult{
		{File: "a.json", Success: true},
		{File: "b.json", Success: true},
		{File: "c.json", Success: false, Error: "parse error"},
	}
	passed, failed := bulkSummaryCounts(results)
	assert.Equal(t, 2, passed)
	assert.Equal(t, 1, failed)
}

// --- CLI integration tests for multi-file validate ---

func TestValidateMultiFile_AllPass(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	stdout, _, err := executeCommand("validate", fixture, fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestValidateMultiFile_SomeFail(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	_, _, err := executeCommand("validate", fixture, badFile)
	require.Error(t, err, "should exit non-zero when any file fails")
}

func TestValidateMultiFile_JSONOutput(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	stdout, _, _ := executeCommand("validate", "--json", fixture, badFile)
	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 2)
}

func TestValidateSingleFile_Unchanged(t *testing.T) {
	// Single-file behavior must remain identical (no "Results:" summary).
	fixture := testFixturePath(t, "minimal-v2.json")
	stdout, _, err := executeCommand("validate", fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "valid HDF results file")
	assert.NotContains(t, stdout, "Results:")
}

// --- CLI integration tests for multi-file list ---

func TestListMultiFile(t *testing.T) {
	fixture := writeRichFixture(t)

	stdout, _, err := executeCommand("list", fixture, fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestListMultiFile_JSONOutput(t *testing.T) {
	fixture := writeRichFixture(t)

	stdout, _, err := executeCommand("list", "--json", fixture, fixture)
	require.NoError(t, err)
	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 2)
}

func TestListSingleFile_Unchanged(t *testing.T) {
	fixture := writeRichFixture(t)
	stdout, _, err := executeCommand("list", fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Baselines:")
	assert.NotContains(t, stdout, "Results:")
}

// --- CLI integration tests for multi-file query ---

func TestQueryMultiFile(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	stdout, _, err := executeCommand("query", fixture, fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestQueryMultiFile_JSONOutput(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	stdout, _, err := executeCommand("query", "--json", fixture, fixture)
	require.NoError(t, err)
	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 2)
}

func TestQuerySingleFile_Unchanged(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	stdout, _, err := executeCommand("query", fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "matching requirement")
	assert.NotContains(t, stdout, "Results:")
}

// --- Glob expansion in CLI commands ---

func TestValidateMultiFile_GlobExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	// Create two valid HDF files
	fixture := testFixturePath(t, "minimal-v2.json")
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "scan1.json"), data, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "scan2.json"), data, 0o600))

	pattern := filepath.Join(tmpDir, "*.json")
	stdout, _, err := executeCommand("validate", pattern)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestValidateMultiFile_AbortsOnFirstFailure(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	// Without -k, should abort on the bad file.
	_, _, err := executeCommand("validate", badFile, fixture)
	require.Error(t, err)
}

func TestValidateMultiFile_ContinuesWithDashK(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	// With -k, should process all files and show summary.
	stdout, _, err := executeCommand("validate", "-k", badFile, fixture)
	require.Error(t, err)
	assert.Contains(t, stdout, "Results: 1/2")
}

// --- Bulk convert tests ---

func TestConvertBulk_MultipleFiles(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	// Copy fixture twice with different names
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	f1 := filepath.Join(tmpDir, "scan1.json")
	f2 := filepath.Join(tmpDir, "scan2.json")
	require.NoError(t, os.WriteFile(f1, data, 0o600))
	require.NoError(t, os.WriteFile(f2, data, 0o600))

	outDir := filepath.Join(tmpDir, "output")
	_, _, err = executeCommand("convert", "--from", "legacyhdf", f1, f2, "-o", outDir, "-k")
	require.NoError(t, err)

	// Check output files exist with .hdf.json suffix
	_, err = os.Stat(filepath.Join(outDir, "scan1.hdf.json"))
	require.NoError(t, err, "scan1.hdf.json should exist")
	_, err = os.Stat(filepath.Join(outDir, "scan2.hdf.json"))
	require.NoError(t, err, "scan2.hdf.json should exist")
}

func TestConvertBulk_RequiresOutputDir(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	f1 := filepath.Join(tmpDir, "a.json")
	f2 := filepath.Join(tmpDir, "b.json")
	require.NoError(t, os.WriteFile(f1, data, 0o600))
	require.NoError(t, os.WriteFile(f2, data, 0o600))

	// Without -o, bulk convert should error
	_, _, err = executeCommand("convert", "--from", "legacyhdf", f1, f2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output-directory")
}

func TestConvertBulk_AbortsWithoutK(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	good := filepath.Join(tmpDir, "good.json")
	bad := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(good, data, 0o600))
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	outDir := filepath.Join(tmpDir, "output")
	// Bad file first, no -k — should abort
	_, _, err = executeCommand("convert", "--from", "legacyhdf", bad, good, "-o", outDir)
	require.Error(t, err)

	// Good file should NOT have been processed
	_, statErr := os.Stat(filepath.Join(outDir, "good.hdf.json"))
	assert.True(t, os.IsNotExist(statErr), "good.hdf.json should not exist when aborting without -k")
}

func TestConvertBulk_ContinuesWithK(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	good := filepath.Join(tmpDir, "good.json")
	bad := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(good, data, 0o600))
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	outDir := filepath.Join(tmpDir, "output")
	// With -k, should skip bad and convert good
	_, _, err = executeCommand("convert", "--from", "legacyhdf", "-k", bad, good, "-o", outDir)
	require.Error(t, err) // still exits non-zero
	require.Error(t, err)

	// Good file should have been converted
	_, statErr := os.Stat(filepath.Join(outDir, "good.hdf.json"))
	require.NoError(t, statErr, "good.hdf.json should exist with -k")
}

func TestBulkOutputPath(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		input    string
		toFmt    string
		expected string
	}{
		{"nessus to hdf", "/out", "scan.nessus", "hdf", "/out/scan.hdf.json"},
		{"sarif to hdf", "/out", "report.sarif", "hdf", "/out/report.hdf.json"},
		{"json to csv", "/out", "results.json", "csv", "/out/results.hdf.csv"},
		{"no extension", "/out", "scanfile", "hdf", "/out/scanfile.hdf.json"},
		{"nested path", "/out", "/path/to/scan.xml", "hdf", "/out/scan.hdf.json"},
		{"default format", "/out", "scan.xml", "", "/out/scan.hdf.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, filepath.ToSlash(bulkOutputPath(tt.dir, tt.input, tt.toFmt)))
		})
	}
}
