package hdftoxml

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type numberCase struct {
	JSON string `json:"json"`
	Text string `json:"text"`
	Why  string `json:"why"`
}

func loadNumberCases(t *testing.T) []numberCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xml-number-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases []numberCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// Rendering is implemented twice, so the expectations live in one shared file
// both languages read rather than in two hand-kept copies. This side passes
// today: it pins Go against future drift rather than proving the table correct,
// since the table was derived from this implementation and then checked against
// an independent shortest-round-trip renderer.
func TestConvertHDFToXMLNumberTextMatchesSharedTable(t *testing.T) {
	for _, c := range loadNumberCases(t) {
		t.Run(c.JSON, func(t *testing.T) {
			// Raw text, not a Go float: a literal would already have lost the
			// distinction the table is pinning (-0 among them).
			input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,` +
				`"tags":{"n":` + c.JSON + `},` +
				`"descriptions":[{"label":"default","data":"d"}],` +
				`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

			out, err := ConvertHDFToXML(input)
			require.NoError(t, err)
			assert.Contains(t, string(out), "<n>"+c.Text+"</n>", c.Why)
		})
	}
}
