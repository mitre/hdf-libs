package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only the two policy names are accepted, and a wrong one is refused before the
// package is read: the package path here does not exist, so reaching the read would
// report that instead.
func TestArchiveAccess_RejectsAnythingButPrivateOrInherit(t *testing.T) {
	for _, value := range []string{"", "Private", "INHERIT", "public", "0600"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "boe.zip")
			_, _, err := executeCommand("evidence", "bundle", filepath.Join(dir, "missing.json"),
				"-o", out, "--output-access", value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--output-access must be private or inherit")
			entries, readErr := os.ReadDir(dir)
			require.NoError(t, readErr)
			assert.Empty(t, entries, "no staged file and no output")
		})
	}
}
