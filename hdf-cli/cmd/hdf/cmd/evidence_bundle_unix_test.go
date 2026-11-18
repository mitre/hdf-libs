//go:build unix

package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On POSIX a backslash is an ordinary name byte, so "..\..\x.json" is one in-tree file
// that the ".." checks never see as traversal; an extractor that splits on backslash
// writes it two levels above its root. Unix-only because Windows cannot name the file.
func TestEvidenceBundle_RefusesAnEntryNameContainingABackslash(t *testing.T) {
	for _, tc := range []struct{ field, uri string }{
		{"contents", `..%5C..%5Cx.json`},
		{"externalEvidence", `..%5C..%5Cx.json`},
		{"contents", `scans%5Cx.json`},
	} {
		t.Run(tc.field+" "+tc.uri, func(t *testing.T) {
			dir := t.TempDir()
			decoded := map[string]string{
				`..%5C..%5Cx.json`: `..\..\x.json`, `scans%5Cx.json`: `scans\x.json`,
			}[tc.uri]
			data := []byte("{}")
			require.NoError(t, os.WriteFile(filepath.Join(dir, decoded), data, 0o600))
			entry := map[string]any{
				"uri":      tc.uri,
				"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(data))},
			}
			pkg := map[string]any{"name": "backslash"}
			if tc.field == "contents" {
				entry["type"] = "hdf-results"
				pkg["contents"] = []map[string]any{entry}
			} else {
				// contents needs one entry; the same bytes under an ordinary name are carried.
				require.NoError(t, os.WriteFile(filepath.Join(dir, "seed.json"), data, 0o600))
				seed := map[string]any{"type": "hdf-results", "uri": "seed.json", "checksum": entry["checksum"]}
				entry["format"] = "raw-log"
				pkg["contents"] = []map[string]any{seed}
				pkg["externalEvidence"] = []map[string]any{entry}
			}
			raw, err := json.Marshal(pkg)
			require.NoError(t, err)
			pkgPath := filepath.Join(dir, "evidence.json")
			require.NoError(t, os.WriteFile(pkgPath, raw, 0o600))

			out := filepath.Join(dir, "out.zip")
			_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", out)
			require.Error(t, err, "the bundle must be refused; stderr: %s", stderr)
			assert.Contains(t, err.Error(), tc.uri, "the refusal names the recorded reference")
			assert.Contains(t, err.Error(), "backslash", "and says why")
			assert.NoFileExists(t, out, "nothing is written")
		})
	}
}

// A staged archive that cannot be created is reported as -o and the operation that
// failed; the staged file's name, which the operator never typed, is left out.
func TestEvidenceBundle_StagingFailureNamesOutputNotTheStagedFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root creates files in a read-only directory")
	}
	dir, pkgPath := bundleTree(t)
	sealed := filepath.Join(dir, "sealed")
	require.NoError(t, os.Mkdir(sealed, 0o500))
	out := filepath.Join(sealed, "boe.zip")

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-o "+out, "the error names -o")
	assert.Contains(t, err.Error(), "open: permission denied", "and the operation that failed")
	assert.NotContains(t, err.Error(), stagedArchivePrefix, "but never the staged file")
}
