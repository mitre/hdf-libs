package hdftoocsf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// classSchemas loads the vendored OCSF schema for each class this converter
// emits. See ../schemas/provenance.txt for the source and the version note.
func classSchemas(t *testing.T) map[float64]*gojsonschema.Schema {
	t.Helper()
	out := map[float64]*gojsonschema.Schema{}
	for uid, file := range map[float64]string{
		classVulnerability: "ocsf-vulnerability_finding-2002.schema.json",
		classCompliance:    "ocsf-compliance_finding-2003.schema.json",
	} {
		path := filepath.Join(shared.GetConvertersDir(), "hdf-to-ocsf", "schemas", file)
		raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative vendored schema
		require.NoError(t, err)
		schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(raw))
		require.NoError(t, err)
		out[uid] = schema
	}
	return out
}

// knownViolations is the EXACT set of schema violations this converter still
// produces, tracked as hdf-libs-5gri.42. It is pinned rather than tolerated: a
// new violation fails this test, and fixing one fails it too, so the list cannot
// drift in either direction without someone noticing.
//
// None of these is a version artifact. The version-pinned OCSF metaschema shows
// evidences and remediation absent from class 2002, and cloud and osint required,
// in BOTH 1.8.0 (which this converter self-declares) and 1.9.0 (vendored).
var knownViolations = map[string]bool{
	"2002|additional_property_not_allowed|Additional property evidences is not allowed":   true,
	"2002|additional_property_not_allowed|Additional property remediation is not allowed": true,
	"2002|required|cloud is required": true,
	"2002|required|osint is required": true,
	"2003|required|cloud is required": true,
	"2003|required|osint is required": true,
}

// violationsFor validates one NDJSON document set and returns the distinct
// violation keys it produced.
func violationsFor(t *testing.T, schemas map[float64]*gojsonschema.Schema, out []byte) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &doc), "converter emitted a line that is not JSON")

		uid, ok := doc["class_uid"].(float64)
		require.True(t, ok, "every finding must carry a numeric class_uid")
		schema, known := schemas[uid]
		require.True(t, known, "converter emitted class_uid %.0f with no vendored schema", uid)

		result, err := schema.Validate(gojsonschema.NewGoLoader(doc))
		require.NoError(t, err)
		for _, e := range result.Errors() {
			seen[fmt.Sprintf("%.0f|%s|%s", uid, e.Type(), e.Description())] = true
		}
	}
	return seen
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Output is validated against the vendored schema for the class it declares.
// The converter is not yet conformant, so this asserts the violation set EXACTLY
// matches the carded one — which catches a regression and equally catches the
// fix, forcing this pin to be retired deliberately.
func TestConvertHDFToOCSF_SchemaValid(t *testing.T) {
	schemas := classSchemas(t)
	dir := filepath.Join(shared.GetConvertersDir(), "hdf-to-ocsf", "fixtures", "input")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "no fixtures — the run would prove nothing")

	all := map[string]bool{}
	for _, e := range entries {
		in, readErr := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- repo-relative fixture
		require.NoError(t, readErr)
		out, convErr := ConvertHDFToOCSF(in, converterVersion)
		if convErr != nil {
			continue // rejection is a separate contract, exercised by the corpus below
		}
		for k := range violationsFor(t, schemas, out) {
			all[k] = true
		}
	}
	assert.Equal(t, sortedKeys(knownViolations), sortedKeys(all),
		"OCSF violation set changed. A NEW entry is a regression; a MISSING one means "+
			"hdf-libs-5gri.42 was fixed and this pin should be reduced to plain validation.")
}

// pinnedSchemaValidator accepts a document only if every schema violation it
// produces is one of the carded ones. That lets the corpus run its full
// contracts -- including MustReject, which a bare NotPanics check silently
// discards -- while a converter that is not yet conformant.
type pinnedSchemaValidator struct {
	t       *testing.T
	schemas map[float64]*gojsonschema.Schema
}

func (v pinnedSchemaValidator) Validate(doc []byte) error {
	// Errors rather than require.*: RunSchemaCorpus calls this from inside its
	// t.Run subtests, and testing.T.FailNow must run on its own test's goroutine.
	seen, err := violationKeys(v.schemas, doc)
	if err != nil {
		return err
	}
	for k := range seen {
		if !knownViolations[k] {
			return fmt.Errorf("new schema violation not in the carded set: %s", k)
		}
	}
	return nil
}

// violationKeys is violationsFor without the assertions, for use off the test's
// own goroutine.
func violationKeys(schemas map[float64]*gojsonschema.Schema, out []byte) (map[string]bool, error) {
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			return nil, fmt.Errorf("converter emitted a line that is not JSON: %w", err)
		}
		uid, ok := doc["class_uid"].(float64)
		if !ok {
			return nil, fmt.Errorf("finding carries no numeric class_uid")
		}
		schema, known := schemas[uid]
		if !known {
			return nil, fmt.Errorf("converter emitted class_uid %.0f with no vendored schema", uid)
		}
		result, err := schema.Validate(gojsonschema.NewGoLoader(doc))
		if err != nil {
			return nil, err
		}
		for _, e := range result.Errors() {
			seen[fmt.Sprintf("%.0f|%s|%s", uid, e.Type(), e.Description())] = true
		}
	}
	return seen, nil
}

// The adversarial corpus holds this converter to all three contracts. Output is
// schema-validated as it goes, minus the carded violations -- so corpus output
// is checked, not merely produced, and an invalid document the converter should
// have rejected still fails.
func TestConvertHDFToOCSF_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, pinnedSchemaValidator{t: t, schemas: classSchemas(t)},
		corpus.ResultsCorpus(), func(in []byte) ([]byte, error) {
			return ConvertHDFToOCSF(in, converterVersion)
		})
}
