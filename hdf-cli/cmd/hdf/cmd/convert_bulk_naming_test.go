package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stageScans writes the same fixture at each of the given root-relative paths
// and returns the absolute input paths in order.
func stageScans(t *testing.T, rels ...string) []string {
	t.Helper()
	data, err := os.ReadFile(legacyhdfFixturePath(t, "input/minimal.json"))
	require.NoError(t, err)
	root := t.TempDir()
	paths := make([]string, 0, len(rels))
	for _, rel := range rels {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, data, 0o600))
		paths = append(paths, p)
	}
	return paths
}

func convertBulk(t *testing.T, outDir string, extraArgs []string, inputs ...string) (stdout, stderr string) {
	t.Helper()
	args := append([]string{"convert", "--from", "legacyhdf"}, extraArgs...)
	args = append(args, inputs...)
	args = append(args, "-o", outDir)
	stdout, stderr, err := executeCommand(args...)
	require.NoError(t, err)
	return stdout, stderr
}

// Two per-host scans with one file name are both converted, each output numbered
// in argument order. Neither is left bare — which input got the unnumbered name
// would otherwise be an arbitrary detail a reader has to know.
func TestConvertBulk_SameBasenameInputsAreNumbered(t *testing.T) {
	inputs := stageScans(t, "host1/scan.json", "host2/scan.json")
	outDir := filepath.Join(t.TempDir(), "out")

	convertBulk(t, outDir, nil, inputs...)

	assert.FileExists(t, filepath.Join(outDir, "scan.1.hdf.json"))
	assert.FileExists(t, filepath.Join(outDir, "scan.2.hdf.json"))
	assert.NoFileExists(t, filepath.Join(outDir, "scan.hdf.json"),
		"no member of a colliding group keeps the plain name")
}

// The number is positional, so the command has to say which input produced
// which file; the per-input result line names only the input.
func TestConvertBulk_NumberedOutputsAreReported(t *testing.T) {
	inputs := stageScans(t, "host1/scan.json", "host2/scan.json")
	outDir := filepath.Join(t.TempDir(), "out")

	_, stderr := convertBulk(t, outDir, nil, inputs...)

	assert.Contains(t, stderr, "Inputs share an output name; numbering them in argument order:")
	assert.Contains(t, stderr, inputs[0]+" -> scan.1.hdf.json")
	assert.Contains(t, stderr, inputs[1]+" -> scan.2.hdf.json")
}

// Nothing is reported when nothing was numbered — the common case stays quiet.
func TestConvertBulk_NoMappingReportedWithoutACollision(t *testing.T) {
	inputs := stageScans(t, "alpha.json", "beta.json")
	outDir := filepath.Join(t.TempDir(), "out")

	_, stderr := convertBulk(t, outDir, nil, inputs...)

	assert.NotContains(t, stderr, "numbering them in argument order")
	assert.FileExists(t, filepath.Join(outDir, "alpha.hdf.json"))
	assert.FileExists(t, filepath.Join(outDir, "beta.hdf.json"))
}

// Numbering carries the non-HDF target extension and sits before it.
func TestConvertBulk_SameBasenameNonHDFTarget(t *testing.T) {
	inputs := stageScans(t, "host1/scan.json", "host2/scan.json")
	outDir := filepath.Join(t.TempDir(), "out")

	convertBulk(t, outDir, []string{"--to", "csv"}, inputs...)

	assert.FileExists(t, filepath.Join(outDir, "scan.1.hdf.csv"))
	assert.FileExists(t, filepath.Join(outDir, "scan.2.hdf.csv"))
}

// Numbering must not take a name a literal input already owns.
func TestConvertBulk_NumberingSkipsALiteralName(t *testing.T) {
	inputs := stageScans(t, "a/scan.json", "b/scan.json", "scan.1.json")
	outDir := filepath.Join(t.TempDir(), "out")

	convertBulk(t, outDir, nil, inputs...)

	assert.FileExists(t, filepath.Join(outDir, "scan.2.hdf.json"))
	assert.FileExists(t, filepath.Join(outDir, "scan.3.hdf.json"))
	assert.FileExists(t, filepath.Join(outDir, "scan.1.hdf.json"))
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	assert.Len(t, entries, 3, "three inputs must produce three distinct outputs")
}

// Distinct basenames keep the plain convention — the common case is unchanged.
func TestConvertBulk_DistinctBasenamesKeepPlainNames(t *testing.T) {
	inputs := stageScans(t, "alpha.json", "beta.json")
	outDir := filepath.Join(t.TempDir(), "out")

	convertBulk(t, outDir, nil, inputs...)

	assert.FileExists(t, filepath.Join(outDir, "alpha.hdf.json"))
	assert.FileExists(t, filepath.Join(outDir, "beta.hdf.json"))
}

// The same file given twice is one conversion with one unnumbered output.
func TestConvertBulk_RepeatedInputTolerated(t *testing.T) {
	inputs := stageScans(t, "host1/scan.json")
	outDir := filepath.Join(t.TempDir(), "out")

	convertBulk(t, outDir, nil, inputs[0], inputs[0])

	assert.FileExists(t, filepath.Join(outDir, "scan.hdf.json"))
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "a repeated input must not produce a numbered second output")
}

// Re-running the same command must land the same bytes in the same file; a
// positional number that drifted between runs would silently swap two reports.
func TestConvertBulk_RepeatedRunIsStable(t *testing.T) {
	inputs := stageScans(t, "host1/scan.json", "host2/scan.json")
	first := filepath.Join(t.TempDir(), "out")
	second := filepath.Join(t.TempDir(), "out")

	convertBulk(t, first, nil, inputs...)
	convertBulk(t, second, nil, inputs...)

	for _, name := range []string{"scan.1.hdf.json", "scan.2.hdf.json"} {
		a, err := os.ReadFile(filepath.Join(first, name)) // #nosec G304 -- test-controlled path
		require.NoError(t, err)
		b, err := os.ReadFile(filepath.Join(second, name)) // #nosec G304 -- test-controlled path
		require.NoError(t, err)
		assert.Equal(t, string(a), string(b), "%s differed between runs", name)
	}
}
