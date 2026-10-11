package hdfvalidators

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `extensions` is closed, and the two shipped validators must enforce that
// identically — the Go one is a draft-07 engine that silently ignores
// `unevaluatedProperties`, so a closure written that way would hold in
// TypeScript alone. Both languages read testdata/shipped-extensions-cases.json.
type shippedExtensionsCase struct {
	Name       string         `json:"name"`
	Extensions map[string]any `json:"extensions"`
	Valid      bool           `json:"valid"`
	Why        string         `json:"why"`
}

func extensionsCaseDocument(t *testing.T, ext map[string]any, atBaseline bool) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(resultsWith(""), &doc))
	if atBaseline {
		doc["baselines"].([]any)[0].(map[string]any)["extensions"] = ext
	} else {
		doc["extensions"] = ext
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func TestValidateResults_ExtensionsIsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "shipped-extensions-cases.json"))
	require.NoError(t, err, "read the shared extensions table")
	var table struct {
		Cases []shippedExtensionsCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	for _, tc := range table.Cases {
		for _, site := range []struct {
			label      string
			atBaseline bool
		}{{"root", false}, {"baseline", true}} {
			t.Run(tc.Name+"/"+site.label, func(t *testing.T) {
				result := ValidateResults(extensionsCaseDocument(t, tc.Extensions, site.atBaseline))
				assert.Equal(t, tc.Valid, result.Valid, "%s\ngot: %s", tc.Why, result.Error())
			})
		}
	}
}
