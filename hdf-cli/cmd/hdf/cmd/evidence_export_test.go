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

// exportPackage writes the given documents under dir and an evidence package
// listing each uri with its content type; a nil body records a reference only.
func exportPackage(t *testing.T, dir string, entries []exportEntry) string {
	t.Helper()
	contents := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		if e.body != nil {
			path := filepath.Join(dir, filepath.FromSlash(e.uri))
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
			require.NoError(t, os.WriteFile(path, e.body, 0o600))
		}
		contents = append(contents, map[string]interface{}{"type": e.docType, "uri": e.uri})
	}
	raw, err := json.Marshal(map[string]interface{}{"name": "export-test", "contents": contents})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(pkgPath, raw, 0o600))
	return pkgPath
}

type exportEntry struct {
	docType, uri string
	body         []byte
}

func outputNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// Every entry exported to one fixed name, so a package with two results documents kept
// only the last while reporting both exported. Each output is now named for its source.
func TestEvidenceExport_WritesEachDocumentToItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	pkgPath := exportPackage(t, dir, []exportEntry{
		{"hdf-results", "scans/grype-results.json", fixtures.Results.MergeGrype},
		{"hdf-results", "scans/zap-results.json", fixtures.Results.MergeZap},
		{"hdf-amendments", "waivers.json", fixtures.Amendments.UC01Fixed},
	})
	outDir := filepath.Join(dir, "out")

	_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
	require.NoError(t, err, stderr)

	assert.ElementsMatch(t, []string{
		"grype-results.oscal-sar.json", "zap-results.oscal-sar.json", "waivers.oscal-poam.json",
	}, outputNames(t, outDir))
	assert.Contains(t, stderr, "3 documents exported")

	// Each SAR is the conversion of its own source, not a survivor of an overwrite.
	for name, src := range map[string][]byte{
		"grype-results.oscal-sar.json": fixtures.Results.MergeGrype,
		"zap-results.oscal-sar.json":   fixtures.Results.MergeZap,
	} {
		var source struct {
			Baselines []struct {
				Name string `json:"name"`
			} `json:"baselines"`
		}
		require.NoError(t, json.Unmarshal(src, &source))
		require.NotEmpty(t, source.Baselines)
		got, readErr := os.ReadFile(filepath.Join(outDir, name))
		require.NoError(t, readErr)
		assert.Contains(t, string(got), source.Baselines[0].Name, name)
	}
}

// Two sources with one base name would export to one file. That is refused before
// anything is written, naming both references, rather than silently keeping one.
func TestEvidenceExport_RefusesAnOutputNameCollision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first, sec string
		wantOutput string
	}{
		{"same base name in two directories", "rhel9/results.json", "postgres/results.json",
			"results.oscal-sar.json"},
		// A case-insensitive volume would make these one file, so they collide everywhere.
		{"base names differing only in case", "Results.json", "nested/results.json",
			"results.oscal-sar.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pkgPath := exportPackage(t, dir, []exportEntry{
				{"hdf-results", tc.first, fixtures.Results.MergeGrype},
				{"hdf-results", tc.sec, fixtures.Results.MergeZap},
			})
			outDir := filepath.Join(dir, "out")

			_, _, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.first)
			assert.Contains(t, err.Error(), tc.sec)
			assert.Contains(t, err.Error(), tc.wantOutput)
			assert.Empty(t, outputNames(t, outDir), "nothing may be written when names collide")
		})
	}
}

// When every convertible entry fails, the run reported "package has no hdf-results"
// and exited 0. It now fails, and says the documents were present.
func TestEvidenceExport_FailsWhenNoConvertibleDocumentExports(t *testing.T) {
	dir := t.TempDir()
	pkgPath := exportPackage(t, dir, []exportEntry{
		{"hdf-results", "rhel9-results.json", nil},
		{"hdf-amendments", "waivers.json", nil},
	})

	_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", filepath.Join(dir, "out"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none of the 2 hdf-results/hdf-amendments documents")
	assert.NotContains(t, stderr, "package has no hdf-results")
	assert.Contains(t, stderr, "could not read rhel9-results.json")
	assert.Contains(t, stderr, "could not read waivers.json")
}

// A partial export is reported as partial: the count names the failures too.
func TestEvidenceExport_CountsOnlyWhatWasExported(t *testing.T) {
	dir := t.TempDir()
	pkgPath := exportPackage(t, dir, []exportEntry{
		{"hdf-results", "grype-results.json", fixtures.Results.MergeGrype},
		{"hdf-results", "missing-results.json", nil},
	})
	outDir := filepath.Join(dir, "out")

	_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
	var exitErr *exitCodeError
	require.ErrorAs(t, err, &exitErr, "a mixed run must not report success")
	assert.Equal(t, exitPartial, exitErr.code)
	assert.Contains(t, stderr, "1 of 2 documents exported")
	assert.Contains(t, stderr, "1 failed")
	assert.Equal(t, []string{"grype-results.oscal-sar.json"}, outputNames(t, outDir))
}

// A package with nothing convertible is not a failure; the message says so.
func TestEvidenceExport_NothingConvertibleIsNotAFailure(t *testing.T) {
	dir := t.TempDir()
	pkgPath := exportPackage(t, dir, []exportEntry{
		{"hdf-baseline", "baseline.json", fixtures.Baseline.Win2022Stig},
	})

	_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", filepath.Join(dir, "out"))
	require.NoError(t, err)
	assert.Contains(t, stderr, "package has no hdf-results or hdf-amendments")
}
