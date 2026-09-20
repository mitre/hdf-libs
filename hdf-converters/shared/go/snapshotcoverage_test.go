package shared

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deleting a golden whose input still exists used to remove its subtest silently:
// the harness only ever discovered goldens. Mirrors shared/typescript/snapshot.test.ts.
func coverageFixtures(t *testing.T, files map[string]string, manifest *string) (inputDir, expectedDir, manifestPath string) {
	t.Helper()
	root := t.TempDir()
	inputDir = filepath.Join(root, "input")
	expectedDir = filepath.Join(root, "expected")
	require.NoError(t, os.Mkdir(inputDir, 0o750))
	require.NoError(t, os.Mkdir(expectedDir, 0o750))
	for name, where := range files {
		require.NoError(t, os.WriteFile(filepath.Join(root, where, name), []byte("{}"), 0o600))
	}
	manifestPath = filepath.Join(root, "no-golden.txt")
	if manifest != nil {
		require.NoError(t, os.WriteFile(manifestPath, []byte(*manifest), 0o600))
	}
	return inputDir, expectedDir, manifestPath
}

func str(s string) *string { return &s }

func TestCheckGoldenCoverage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		files    map[string]string
		manifest *string
		want     []string
	}{
		{"reports an input whose golden is missing",
			map[string]string{"a.json": "input", "a.json.hdf.json": "expected", "b.json": "input"}, nil,
			[]string{"input b.json has no golden expected/b.json.hdf.json and no entry in no-golden.txt"}},
		{"accepts the empty.* convention without a manifest",
			map[string]string{"empty.json": "input", "empty.xml": "input", "a.json": "input", "a.json.hdf.json": "expected"}, nil, nil},
		{"accepts an input the manifest records, with a reason",
			map[string]string{"b.json": "input"}, str("b.json — used by TestX, which asserts an error\n"), nil},
		{"rejects a manifest entry that names no input, so the list cannot rot",
			map[string]string{}, str("gone.json — once here\n"),
			[]string{"no-golden.txt names gone.json, which is not in input/ — remove the entry"}},
		{"rejects a manifest entry for an input that has a golden after all",
			map[string]string{"a.json": "input", "a.json.hdf.json": "expected"}, str("a.json — no golden\n"),
			[]string{"no-golden.txt names a.json, but expected/a.json.hdf.json exists — remove the entry"}},
		{"rejects a manifest entry without a reason",
			map[string]string{"b.json": "input"}, str("b.json\n"),
			[]string{"no-golden.txt entry for b.json gives no reason — write one after \" — \""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, ex, mf := coverageFixtures(t, c.files, c.manifest)
			got, err := checkGoldenCoverage(in, ex, mf)
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}
