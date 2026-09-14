package exportmap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The SIEM exporters emit numbers straight into NDJSON, so Go's encoding/json
// rendering IS the output contract. shared/export-number-cases.json pins that
// contract and the TypeScript peer asserts the same table, which is what stops
// the two languages drifting on a value no fixture happens to carry.
type exportNumberCase struct {
	JSON  string `json:"json"`
	Token string `json:"token"`
	Why   string `json:"why"`
}

type exportNumberTable struct {
	Cases      []exportNumberCase `json:"cases"`
	FloatCases []exportNumberCase `json:"floatTokenCases"`
}

func loadExportNumberTable(t *testing.T) exportNumberTable {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "export-number-cases.json"))
	require.NoError(t, err, "shared number table is unreadable")
	var table exportNumberTable
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)
	require.NotEmpty(t, table.FloatCases)
	return table
}

// parseNumber decodes a raw JSON number exactly as the export driver does: into
// an interface{}, which yields a float64 and preserves the sign of a negative
// zero that a JavaScript literal would have already lost.
func parseNumber(t *testing.T, text string) interface{} {
	t.Helper()
	var v interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &v), "case %q is not valid JSON", text)
	return v
}

func TestExportNumberTableMatchesGoEncoder(t *testing.T) {
	for _, c := range loadExportNumberTable(t).Cases {
		t.Run(c.JSON, func(t *testing.T) {
			line, err := EncodeLine(map[string]interface{}{"v": parseNumber(t, c.JSON)})
			require.NoError(t, err)
			assert.Equal(t, "{\"v\":"+c.Token+"}\n", string(line), c.Why)
		})
	}
}

func TestExportNumberTableMatchesFloatToken(t *testing.T) {
	for _, c := range loadExportNumberTable(t).FloatCases {
		t.Run(c.JSON, func(t *testing.T) {
			f, ok := parseNumber(t, c.JSON).(float64)
			require.True(t, ok, "float case must decode to a float64")
			assert.Equal(t, json.Number(c.Token), FloatToken(f), c.Why)
		})
	}
}
