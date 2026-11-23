package generators

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rubyTagCase struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	Line  string `json:"line"`
	Why   string `json:"why"`
}

// The TypeScript peer (formatTag) asserts against this same table.
func loadRubyTagCases(t *testing.T) []rubyTagCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "ruby-tag-cases.json"))
	require.NoError(t, err)
	var table struct {
		Cases []rubyTagCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "empty table would pass vacuously")
	return table.Cases
}

func TestFormatTag_SharedTable(t *testing.T) {
	for _, c := range loadRubyTagCases(t) {
		assert.Equal(t, c.Line, formatTag(c.Key, c.Value), c.Why)
	}
}

// Ruby loads every tag line under the control-DSL stand-in and must read back
// the same key and value.
func TestFormatTag_RubyReadsTagsBack(t *testing.T) {
	cases := loadRubyTagCases(t)
	var script strings.Builder
	script.WriteString("require 'json'\n$t = []\ndef tag(h) h.each { |k, v| $t << [k.to_s, v] } end\n")
	for _, c := range cases {
		script.WriteString(formatTag(c.Key, c.Value) + "\n")
	}
	script.WriteString("STDOUT.write(JSON.generate($t))\n")

	var got [][2]any
	require.NoError(t, json.Unmarshal(runRuby(t, script.String()), &got))
	require.Len(t, got, len(cases))
	for i, c := range cases {
		assert.Equal(t, c.Key, got[i][0], c.Why)
		assert.Equal(t, c.Value, got[i][1], c.Why)
	}
}

// JSON cannot carry NaN or infinity, but a Go caller filling Tags can; Ruby
// spells them as Float constants.
func TestRubyValue_NonFinite(t *testing.T) {
	assert.Equal(t, "Float::NAN", rubyValue(math.NaN()))
	assert.Equal(t, "Float::INFINITY", rubyValue(math.Inf(1)))
	assert.Equal(t, "-Float::INFINITY", rubyValue(math.Inf(-1)))
	runRuby(t, "p([Float::NAN, Float::INFINITY, -Float::INFINITY])\n")
}
