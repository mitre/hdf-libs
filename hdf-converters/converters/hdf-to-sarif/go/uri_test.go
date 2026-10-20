package hdftosarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

type uriCase struct {
	Input     string `json:"input"`
	Reference string `json:"reference"`
	Absolute  string `json:"absolute"`
	Why       string `json:"why"`
}

func uriCases(t *testing.T) []uriCase {
	t.Helper()
	path := filepath.Join("..", "fixtures", "uri-reference-cases.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative case table
	require.NoError(t, err)
	var table struct {
		Cases []uriCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)
	return table.Cases
}

// The TypeScript peer reads the same table, which is what stops the two
// languages drifting on a value no fixture happens to carry.
func TestURIRendering_MatchesTheSharedTable(t *testing.T) {
	for _, c := range uriCases(t) {
		assert.Equal(t, c.Reference, EncodeURIReference(c.Input), "uri-reference: %s", c.Why)
		assert.Equal(t, c.Absolute, AbsoluteURI(c.Input), "uri: %s", c.Why)
	}
}

// The table's point is that the output satisfies the formats the SARIF schema
// asserts, so the validator itself is the judge rather than the expectation.
func TestURIRendering_OutputSatisfiesTheSchemaFormats(t *testing.T) {
	refSchema, err := gojsonschema.NewSchema(gojsonschema.NewStringLoader(
		`{"type":"string","format":"uri-reference"}`))
	require.NoError(t, err)
	absSchema, err := gojsonschema.NewSchema(gojsonschema.NewStringLoader(
		`{"type":"string","format":"uri"}`))
	require.NoError(t, err)

	for _, c := range uriCases(t) {
		encoded, err := json.Marshal(EncodeURIReference(c.Input))
		require.NoError(t, err)
		res, err := refSchema.Validate(gojsonschema.NewBytesLoader(encoded))
		require.NoError(t, err)
		assert.True(t, res.Valid(), "uri-reference rejected %q (%v)", string(encoded), res.Errors())

		if abs := AbsoluteURI(c.Input); abs != "" {
			encoded, err = json.Marshal(abs)
			require.NoError(t, err)
			res, err = absSchema.Validate(gojsonschema.NewBytesLoader(encoded))
			require.NoError(t, err)
			assert.True(t, res.Valid(), "uri rejected %q (%v)", string(encoded), res.Errors())
		}
	}
}

// Encoding is reversible: that is what makes it a rendering rather than a
// rewrite of the value.
func TestEncodeURIReference_IsIdempotent(t *testing.T) {
	for _, c := range uriCases(t) {
		once := EncodeURIReference(c.Input)
		assert.Equal(t, once, EncodeURIReference(once), "%s", c.Why)
	}
}
