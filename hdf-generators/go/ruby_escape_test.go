package generators

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rubyLiteralCase struct {
	Input   string `json:"input"`
	Literal string `json:"literal"`
	Why     string `json:"why"`
}

// The TypeScript peer (escapeQuotes) asserts against this same table.
func loadRubyLiteralCases(t *testing.T) []rubyLiteralCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "ruby-literal-cases.json"))
	require.NoError(t, err)
	var table struct {
		Cases []rubyLiteralCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "empty table would pass vacuously")
	return table.Cases
}

func TestEscapeQuotes_SharedTable(t *testing.T) {
	for _, c := range loadRubyLiteralCases(t) {
		assert.Equal(t, c.Literal, EscapeQuotes(c.Input), c.Why)
	}
}

// Syntax validity does not prove the value is unchanged, so Ruby itself reads
// every literal back and the value must equal the input.
func TestEscapeQuotes_RubyReadsInputBack(t *testing.T) {
	cases := loadRubyLiteralCases(t)
	var script strings.Builder
	script.WriteString("require 'json'\nSTDOUT.write(JSON.generate([\n")
	for _, c := range cases {
		script.WriteString(EscapeQuotes(c.Input))
		script.WriteString(",\n")
	}
	script.WriteString("]))\n")

	var values []string
	require.NoError(t, json.Unmarshal(runRuby(t, script.String()), &values))
	require.Len(t, values, len(cases))
	for i, c := range cases {
		assert.Equal(t, c.Input, values[i], "%s: literal %s", c.Why, EscapeQuotes(c.Input))
	}
}

// runRuby runs script under ruby and returns its stdout, skipping the test
// when ruby is not installed.
func runRuby(t *testing.T, script string) []byte {
	t.Helper()
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby is not installed; the shared table still pins every literal")
	}
	cmd := exec.CommandContext(t.Context(), "ruby", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "ruby rejected the script: %s", stderr.String())
	return out
}
