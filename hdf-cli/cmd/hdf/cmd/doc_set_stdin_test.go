package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every command that writes back to the document it read, by default, used to leave a
// regular file named "-" in the working directory when that document came from stdin.
// Each refuses it the same way, and with -o writes there instead.
func TestInPlaceWriters_RefuseAStdinDocumentWithoutAnOutput(t *testing.T) {
	bom, err := filepath.Abs(bomFixturePath(t, "cyclonedx-mlbom.json"))
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		input func(t *testing.T) []byte
		args  []string
	}{
		{"plan set", func(t *testing.T) []byte { return fixtureBytes(t, "plan.json") },
			[]string{"plan", "set", "-", "--name", "renamed"}},
		{"system set", func(t *testing.T) []byte { return fixtureBytes(t, "system.json") },
			[]string{"system", "set", "-", "--name", "renamed"}},
		{"amend set", func(*testing.T) []byte { return []byte(testAmendmentsForSet) },
			[]string{"amend", "set", "-", "--name", "renamed"}},
		{"label set", func(t *testing.T) []byte { return fixtureBytes(t, "rhel9-results.json") },
			[]string{"label", "set", "-", "env=prod"}},
		{"label remove", func(t *testing.T) []byte { return fixtureBytes(t, "rhel9-results.json") },
			[]string{"label", "remove", "-", "env"}},
		{"system add-component", func(t *testing.T) []byte { return fixtureBytes(t, "system.json") },
			[]string{"system", "add-component", bom, "--system", "-", "--component-name", "Model"}},
		{"system update-component", func(t *testing.T) []byte { return fixtureBytes(t, "system.json") },
			[]string{"system", "update-component", bom, "--system", "-", "--add-new"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.input(t)
			cwd := t.TempDir()
			t.Chdir(cwd)

			_, _, err := executeCommandWithStdin(t, input, tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "reading the document from stdin requires -o <file>")
			assert.NoFileExists(t, filepath.Join(cwd, "-"), "no stray file named - is written")

			out := filepath.Join(cwd, "out.json")
			_, stderr, err := executeCommandWithStdin(t, input, append(tc.args, "-o", out)...)
			require.NoError(t, err, stderr)
			assert.FileExists(t, out, "with -o the stdin document is written there")
			assert.NoFileExists(t, filepath.Join(cwd, "-"))
		})
	}
}
