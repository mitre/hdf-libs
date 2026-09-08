package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type xmlGoldenCase struct {
	Name      string `json:"name"`
	A         string `json:"a"`
	B         string `json:"b"`
	ExpectedA string `json:"expectedA"`
	ExpectedB string `json:"expectedB"`
	Equal     bool   `json:"equal"`
	Why       string `json:"why"`
}

func loadXMLGoldenCases(t *testing.T) []xmlGoldenCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "xml-golden-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases []xmlGoldenCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// The normalizer is implemented twice, and it is the yardstick every XML parity
// assertion in this repo is measured with, so the two copies are held to one
// shared table rather than to each other's behaviour.
func TestNormalizeXMLForGoldenMatchesSharedTable(t *testing.T) {
	for _, c := range loadXMLGoldenCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			a, b := NormalizeXMLForGolden(c.A), NormalizeXMLForGolden(c.B)
			// Against the table's literal, not merely against each other: two
			// implementations returning the same wrong string would satisfy a
			// relation-only assertion, so the peer would be pinned to nothing.
			assert.Equal(t, c.ExpectedA, a, c.Why)
			assert.Equal(t, c.ExpectedB, b, c.Why)
			assert.Equal(t, c.Equal, a == b, c.Why)
		})
	}
}

// The property the masking bug violated, stated directly: normalization may drop
// formatting, but it must never turn content into nothing.
func TestNormalizeXMLForGoldenKeepsWhitespaceContent(t *testing.T) {
	// The members beyond XML's S production: NBSP and U+3000 reach only JavaScript's
	// \s, form feed reaches both, and none has an encoder entry.
	for _, ws := range []string{" ", "\t", "\n", "\r", "  ", "\t\n", "\u00a0", "\u3000", "\u000c", "\u2003"} {
		assert.NotEqual(t,
			NormalizeXMLForGolden("<r><k></k></r>"),
			NormalizeXMLForGolden("<r><k>"+ws+"</k></r>"),
			"whitespace content %q was erased, so an empty element compares equal to one carrying it", ws)
	}
}
