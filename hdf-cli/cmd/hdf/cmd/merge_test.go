package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three real converter expected outputs the engine's merge tests also use:
// gosec (1 baseline, 3 requirements), ZAP webgoat (4 baselines, 28), grype
// tensorflow (1 baseline, 26) — 6 baselines and 57 requirements merged.
func mergeScannerFixtures(t *testing.T) []string {
	t.Helper()
	return []string{
		converterFixturePath(t, "gosec-to-hdf", "expected/real.json.hdf.json"),
		converterFixturePath(t, "zap-to-hdf", "expected/webgoat.json.hdf.json"),
		converterFixturePath(t, "grype-to-hdf", "expected/tensorflow.json.hdf.json"),
	}
}

// baselineFixturePath is the engine's shared baseline (non-results) fixture.
func baselineFixturePath(t *testing.T) string {
	t.Helper()
	path := filepath.Clean(filepath.Join(shared.GetConvertersDir(), "..", "..", "hdf-engine", "testdata", "baseline-fixture.json"))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("baseline fixture not found: %s (%v)", path, err)
	}
	return path
}

func readMergedDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

func mergedBaselineNames(doc map[string]any) []string {
	var names []string
	for _, b := range doc["baselines"].([]any) {
		names = append(names, b.(map[string]any)["name"].(string))
	}
	return names
}

// TestMerge_ThreeScannersOneDocument is js1nv.4's first failing test: the
// command merges the three real fixtures into one file that `hdf validate`
// accepts, with one baseline per input baseline, tool-prefixed names, and
// nothing on stdout.
func TestMerge_ThreeScannersOneDocument(t *testing.T) {
	out := filepath.Join(t.TempDir(), "merged.hdf.json")
	args := append([]string{"merge"}, mergeScannerFixtures(t)...)
	stdout, stderr, err := executeCommand(append(args, "-o", out)...)
	require.NoError(t, err, "stderr: %s", stderr)
	assert.Empty(t, stdout, "a file write prints nothing on stdout")
	assert.Empty(t, stderr, "no warnings for three distinct scanners")

	doc := readMergedDoc(t, out)
	assert.Equal(t, []string{
		"gosec/gosec Scan",
		"owasp zap/OWASP ZAP Scan: ciscobinary.openh264.org",
		"owasp zap/OWASP ZAP Scan: code.jquery.com",
		"owasp zap/OWASP ZAP Scan: detectportal.firefox.com",
		"owasp zap/OWASP ZAP Scan: mymac.com",
		"grype/tensorflow/tensorflow:latest",
	}, mergedBaselineNames(doc))
	gen := doc["generator"].(map[string]any)
	assert.Equal(t, "hdf-merge", gen["name"])
	_, hasTool := doc["tool"]
	assert.False(t, hasTool, "a merged root carries no single tool")

	vstdout, vstderr, err := executeCommand("validate", out)
	require.NoError(t, err, "hdf validate must accept the merged file: %s %s", vstdout, vstderr)
}

// TestMerge_RejectsNonResultsInput: a baseline document among the inputs is an
// error that names the file and the detected type, and no output is written.
func TestMerge_RejectsNonResultsInput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "merged.hdf.json")
	fixtures := mergeScannerFixtures(t)
	_, stderr, err := executeCommand("merge", fixtures[0], baselineFixturePath(t), "-o", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "baseline-fixture.json")
	assert.Contains(t, err.Error(), "results")
	assert.Contains(t, stderr, "Error:")
	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "no partial output on a rejected input")
}

// TestMerge_OverwriteConvention follows hdf convert: an existing OUTPUT is
// overwritten freely; writing over an INPUT is refused unless --force.
func TestMerge_OverwriteConvention(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "gosec.hdf.json")
	src, err := os.ReadFile(mergeScannerFixtures(t)[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(in, src, 0o600))

	// Existing output: overwritten without any flag.
	out := filepath.Join(dir, "out.json")
	require.NoError(t, os.WriteFile(out, []byte("stale"), 0o600))
	_, stderr, err := executeCommand("merge", in, "-o", out)
	require.NoError(t, err, stderr)
	assert.Equal(t, []string{"gosec/gosec Scan"}, mergedBaselineNames(readMergedDoc(t, out)))

	// Output is an input: refused with convert's wording, input left intact.
	_, _, err = executeCommand("merge", in, "-o", in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "would overwrite input file")
	assert.Contains(t, err.Error(), "--force")
	again, err := os.ReadFile(in)
	require.NoError(t, err)
	assert.Equal(t, src, again, "the input must be untouched after a refused write")

	// --force allows it.
	_, stderr, err = executeCommand("merge", in, "-o", in, "--force")
	require.NoError(t, err, stderr)
	assert.Equal(t, []string{"gosec/gosec Scan"}, mergedBaselineNames(readMergedDoc(t, in)))
}

// TestMerge_JSONSummaryAndDeterminism: --json prints the merge summary — never
// the document — and two runs on the same inputs write byte-identical files.
func TestMerge_JSONSummaryAndDeterminism(t *testing.T) {
	dir := t.TempDir()
	fixtures := mergeScannerFixtures(t)
	out1 := filepath.Join(dir, "a.json")
	out2 := filepath.Join(dir, "b.json")

	stdout, stderr, err := executeCommand(append(append([]string{"merge"}, fixtures...), "-o", out1, "--json")...)
	require.NoError(t, err, stderr)
	var summary map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &summary), "stdout: %s", stdout)
	assert.Equal(t, out1, summary["output"])
	assert.Equal(t, float64(6), summary["baselines"])
	assert.Equal(t, float64(57), summary["requirements"])
	assert.Equal(t, float64(5), summary["components"])
	assert.Len(t, summary["sha256"], 64)
	assert.Empty(t, summary["warnings"])
	_, hasBody := summary["baselines"].([]any)
	assert.False(t, hasBody, "the summary carries counts, not the baselines array")

	_, stderr, err = executeCommand(append(append([]string{"merge"}, fixtures...), "-o", out2)...)
	require.NoError(t, err, stderr)
	a, err := os.ReadFile(out1)
	require.NoError(t, err)
	b, err := os.ReadFile(out2)
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b))
}

// TestMerge_StdoutWhenNoOutput: without -o the document itself goes to stdout.
func TestMerge_StdoutWhenNoOutput(t *testing.T) {
	stdout, stderr, err := executeCommand(append([]string{"merge"}, mergeScannerFixtures(t)...)...)
	require.NoError(t, err, stderr)
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
	assert.Len(t, doc["baselines"], 6)
}

// TestMerge_WarningsOnStderr: merging the same scanner twice collides on the
// prefixed name; the merge succeeds and the warning is reported on stderr.
func TestMerge_WarningsOnStderr(t *testing.T) {
	out := filepath.Join(t.TempDir(), "merged.hdf.json")
	gosec := mergeScannerFixtures(t)[0]
	_, stderr, err := executeCommand("merge", gosec, gosec, "-o", out)
	require.NoError(t, err)
	assert.Contains(t, stderr, "duplicate-baseline-name")
	assert.Contains(t, stderr, "gosec/gosec Scan")
	assert.True(t, strings.Contains(stderr, "0") && strings.Contains(stderr, "1"), "the warning names both positions: %s", stderr)
	assert.Equal(t, []string{"gosec/gosec Scan", "gosec/gosec Scan"}, mergedBaselineNames(readMergedDoc(t, out)))
}
