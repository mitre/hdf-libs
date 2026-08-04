package hdfdetect

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schemaExampleDoc returns a real, schema-valid document for the given type,
// sourced from the bundled schema's top-level examples. This satisfies the
// fixture-integrity rule (validated against the official schema) without
// fabricating data. The example's "$comment" annotation is stripped because it
// is documentation metadata, not part of the document (schemas are
// unevaluatedProperties:false and would reject it).
func schemaExampleDoc(t *testing.T, st validators.SchemaType) []byte {
	t.Helper()
	raw, err := validators.SchemaBytes(st)
	require.NoError(t, err)
	var schema struct {
		Examples []map[string]json.RawMessage `json:"examples"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	require.NotEmptyf(t, schema.Examples, "schema %s carries no top-level examples", st)
	ex := schema.Examples[0]
	delete(ex, "$comment")
	doc, err := json.Marshal(ex)
	require.NoError(t, err)
	return doc
}

// minimalComparison mirrors hdf-schema/test/setup.ts createMinimalComparisonDoc —
// the repo-maintained minimal valid hdf-comparison document. The comparison
// schema carries no top-level example, and this card does not change schemas;
// the document is asserted valid against the real schema below, so its
// provenance is the official schema, not fabrication.
const minimalComparison = `{
  "formatVersion": "1.0.0",
  "comparisonMode": "temporal",
  "sources": [
    {"role": "old", "label": "Before scan"},
    {"role": "new", "label": "After scan"}
  ],
  "summary": {"total": 0, "matchedCount": 0, "unmatchedOldCount": 0, "unmatchedNewCount": 0},
  "requirementDiffs": []
}`

// TestDetect_AllEightDocTypes is the first failing test: every one of the eight
// HDF document types — explicitly including requirement-change-event, which the
// original CLI detector never returned — must be classified correctly from a
// real, schema-valid document.
func TestDetect_AllEightDocTypes(t *testing.T) {
	cases := []struct {
		name string
		typ  validators.SchemaType
		doc  []byte // nil → source from the schema's top-level example
	}{
		{"results", validators.TypeResults, nil},
		{"baseline", validators.TypeBaseline, nil},
		{"system", validators.TypeSystem, nil},
		{"plan", validators.TypePlan, nil},
		{"amendments", validators.TypeAmendments, nil},
		{"evidence-package", validators.TypeEvidencePackage, nil},
		{"requirement-change-event", validators.TypeRequirementChangeEvent, nil},
		{"comparison", validators.TypeComparison, []byte(minimalComparison)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := tc.doc
			if doc == nil {
				doc = schemaExampleDoc(t, tc.typ)
			}
			// Provenance guard: the fixture is a real, schema-valid document.
			res := validators.Validate(doc, tc.typ)
			require.Truef(t, res.Valid, "fixture for %s must be schema-valid: %s", tc.typ, res.Error())
			// The assertion under test: detection resolves to the correct type.
			assert.Equalf(t, string(tc.typ), Detect(doc), "detect %s", tc.typ)
		})
	}
}

func TestDetect_UnrecognizedAndInvalid(t *testing.T) {
	assert.Equal(t, "", Detect([]byte(`{}`)), "empty object is unrecognized")
	assert.Equal(t, "", Detect([]byte(`not json`)), "invalid JSON is unrecognized")
	assert.Equal(t, "", Detect([]byte(`{"foo":"bar"}`)), "unknown shape is unrecognized")
}

// TestDetect_NoCobraDependency asserts the package's transitive build-import
// graph contains no cobra — the reason detection is extracted out of package
// cmd (AC1). Test-only imports are excluded from `go list -deps .`.
func TestDetect_NoCobraDependency(t *testing.T) {
	out, err := exec.CommandContext(context.Background(), "go", "list", "-deps", ".").CombinedOutput()
	require.NoErrorf(t, err, "go list failed: %s", out)
	assert.NotContains(t, string(out), "spf13/cobra", "hdfdetect must not depend on cobra")
}
