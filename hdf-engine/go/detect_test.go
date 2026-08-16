package hdfengine

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
//
// The TS port's parity test (src/detect.test.ts) reads the SAME schema examples
// (from @mitre/hdf-schema) and asserts the SAME type→string mapping, so the two
// implementations are held to one shared, schema-derived contract.
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

// TestDetect_AllEightDocTypes classifies every one of the eight HDF document
// types — explicitly including requirement-change-event — from a real,
// schema-valid document. This is the Go side of the cross-language parity
// contract; src/detect.test.ts mirrors it in TypeScript.
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

// TestDetect_KeyPrecedence locks the fixed check order for documents that carry
// more than one discriminator key. This is load-bearing: a real results document
// carries both baselines and components and must classify as results, and the
// change-event quad must win over any other key. Guards against a future reorder
// of the switch (which the card's decision-point forbids).
func TestDetect_KeyPrecedence(t *testing.T) {
	cases := []struct{ name, doc, want string }{
		{"results before system", `{"baselines":[],"components":[]}`, "results"},
		{"change-event quad before baselines", `{"requirementId":"x","state":"updated","before":{},"after":{},"baselines":[]}`, "requirement-change-event"},
		{"evidence before results", `{"contents":[],"baselines":[]}`, "evidence-package"},
		{"amendments before baseline", `{"overrides":[],"requirements":[]}`, "amendments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Detect([]byte(tc.doc)))
		})
	}
}

func TestDetect_UnrecognizedAndInvalid(t *testing.T) {
	assert.Equal(t, "", Detect([]byte(`{}`)), "empty object is unrecognized")
	assert.Equal(t, "", Detect([]byte(`not json`)), "invalid JSON is unrecognized")
	assert.Equal(t, "", Detect([]byte(`{"foo":"bar"}`)), "unknown shape is unrecognized")
}

// TestKnownTypes_MatchesDetect guards that KnownTypes() enumerates exactly the
// set Detect can return — so an "unrecognized document" diagnostic that lists
// KnownTypes() names every type the detector actually accepts, and a future
// detect addition cannot silently drift the two apart.
func TestKnownTypes_MatchesDetect(t *testing.T) {
	want := map[string]bool{
		string(validators.TypeResults): true, string(validators.TypeBaseline): true,
		string(validators.TypeSystem): true, string(validators.TypePlan): true,
		string(validators.TypeAmendments): true, string(validators.TypeEvidencePackage): true,
		string(validators.TypeComparison): true, string(validators.TypeRequirementChangeEvent): true,
	}
	got := KnownTypes()
	assert.Len(t, got, len(want), "KnownTypes count drifted from the detectable set")
	seen := map[string]bool{}
	for _, ty := range got {
		assert.Truef(t, want[ty], "KnownTypes lists %q, which is not a detectable type", ty)
		assert.Falsef(t, seen[ty], "KnownTypes lists %q twice", ty)
		seen[ty] = true
	}
}

// TestDetect_NoCobraDependency asserts the package's transitive build-import
// graph contains no cobra — hdf-engine is a cobra-free library both the CLI and
// the MCP import. Test-only imports are excluded from `go list -deps .`.
func TestDetect_NoCobraDependency(t *testing.T) {
	out, err := exec.CommandContext(context.Background(), "go", "list", "-deps", ".").CombinedOutput()
	require.NoErrorf(t, err, "go list failed: %s", out)
	assert.NotContains(t, string(out), "spf13/cobra", "hdf-engine must not depend on cobra")
}
