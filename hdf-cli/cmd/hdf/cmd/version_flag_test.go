package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVersionFlag asserts the root command exposes --version and its -v
// shorthand, printing the same build-time version string the `hdf version`
// subcommand uses (single source of truth, bead i0gl).
func TestVersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			stdout, _, err := executeCommand(arg)
			require.NoError(t, err)
			assert.Contains(t, stdout, "hdf version")
			assert.Contains(t, stdout, version)
		})
	}
}
