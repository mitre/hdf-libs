package shared

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tekuri "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// SchemaValidator validates JSON documents against a JSON Schema, compiled once
// for reuse across a converter's output tests.
//
// Converters that emit a format with a published schema MUST validate their
// output against it in tests: golden fixtures alone silently encode whatever the
// converter emits, so schema-invalid output ships unnoticed (see the
// hdf-to-oscal-sar regression in GitHub #184, which declared OSCAL 1.1.2
// conformance while failing that schema on four counts).
//
// It dispatches on the schema's declared draft, because no single Go library
// covers the range we need:
//   - draft-07 and earlier → xeipuuv/gojsonschema, which resolves the NIST OSCAL
//     schemas' legacy `$id: "#anchor"` construct that santhosh-tekuri rejects.
//   - 2019-09 / 2020-12 → santhosh-tekuri/jsonschema, which gojsonschema cannot
//     parse (CSAF, OpenVEX).
//
// This matches the ajv-based TypeScript harness, which validates both drafts.
type SchemaValidator struct {
	draft07 *gojsonschema.Schema // draft-07 and earlier
	modern  *tekuri.Schema       // draft 2019-09 / 2020-12
}

// NewSchemaValidator compiles a JSON Schema from a file path, choosing the
// validator from the schema's $schema draft. Prefer a vendored, self-contained
// schema with documented provenance (source URL, version, sha256) so the check
// is reproducible and pinned to the version the converter declares conformance
// to.
func NewSchemaValidator(t *testing.T, schemaPath string) *SchemaValidator {
	t.Helper()
	abs, err := filepath.Abs(schemaPath)
	require.NoError(t, err, "resolve schema path %s", schemaPath)
	raw, err := os.ReadFile(abs) //nolint:gosec // test-only, reads a vendored schema fixture
	require.NoError(t, err, "read schema %s", schemaPath)

	if schemaIsModern(raw) {
		doc, err := tekuri.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err, "parse schema %s", schemaPath)
		// Register/compile under the schema's own $id when present so its
		// internal $refs resolve against the right base URI.
		url := "file://" + abs
		if m, ok := doc.(map[string]any); ok {
			if id, ok := m["$id"].(string); ok && id != "" {
				url = id
			}
		}
		c := tekuri.NewCompiler()
		require.NoError(t, c.AddResource(url, doc), "register schema %s", schemaPath)
		schema, err := c.Compile(url)
		require.NoError(t, err, "compile schema %s", schemaPath)
		return &SchemaValidator{modern: schema}
	}

	schema, err := gojsonschema.NewSchema(gojsonschema.NewReferenceLoader("file://" + abs))
	require.NoError(t, err, "compile schema %s", schemaPath)
	return &SchemaValidator{draft07: schema}
}

// schemaIsModern reports whether the schema declares a 2019-09 or 2020-12 draft.
func schemaIsModern(raw []byte) bool {
	var head struct {
		Schema string `json:"$schema"`
	}
	_ = json.Unmarshal(raw, &head)
	return strings.Contains(head.Schema, "2019-09") || strings.Contains(head.Schema, "2020-12")
}

// RequireValid asserts doc satisfies the schema, reporting every violation on
// failure so a red run pinpoints exactly what is wrong.
func (v *SchemaValidator) RequireValid(t *testing.T, label string, doc []byte) {
	t.Helper()
	if v.modern != nil {
		inst, err := tekuri.UnmarshalJSON(bytes.NewReader(doc))
		require.NoError(t, err, "%s: parse document", label)
		if err := v.modern.Validate(inst); err != nil {
			t.Fatalf("%s: document does not satisfy the schema:\n%v", label, err)
		}
		return
	}

	result, err := v.draft07.Validate(gojsonschema.NewBytesLoader(doc))
	require.NoError(t, err, "%s: schema validation errored", label)
	if result.Valid() {
		return
	}
	for _, e := range result.Errors() {
		t.Errorf("%s: %s: %s", label, e.Field(), e.Description())
	}
	t.Fatalf("%s: document does not satisfy the schema", label)
}
