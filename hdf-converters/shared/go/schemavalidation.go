package shared

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
// converter emits, so schema-invalid output ships unnoticed — as an oscal-sar
// regression once did, declaring OSCAL 1.1.2 conformance while failing that
// schema.
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

// NewSchemaValidator compiles a self-contained JSON Schema from a file path.
// For schemas that $ref external schemas by URL, use
// NewSchemaValidatorWithResources.
func NewSchemaValidator(t *testing.T, schemaPath string) *SchemaValidator {
	return NewSchemaValidatorWithResources(t, schemaPath, nil)
}

// NewSchemaValidatorWithResources compiles a JSON Schema, choosing the validator
// from the schema's $schema draft, and pre-registers companion schemas so a main
// schema that $refs external schemas by URL (e.g. CSAF → FIRST.org CVSS,
// CycloneDX → SPDX/JSF) compiles offline. companions maps each $ref URL exactly
// as it appears in the main schema to the vendored file that satisfies it.
//
// Prefer vendored schemas with documented provenance (source URL, version,
// sha256) so the check is reproducible and pinned to the version the converter
// declares conformance to.
func NewSchemaValidatorWithResources(t *testing.T, schemaPath string, companions map[string]string) *SchemaValidator {
	t.Helper()
	abs, err := filepath.Abs(schemaPath)
	require.NoError(t, err, "resolve schema path %s", schemaPath)
	raw, err := os.ReadFile(abs) //nolint:gosec // test-only, reads a vendored schema fixture
	require.NoError(t, err, "read schema %s", schemaPath)

	if schemaIsModern(raw) {
		doc, err := tekuri.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err, "parse schema %s", schemaPath)
		// Register/compile under the schema's own $id when present so its
		// internal $refs resolve against the right base URI; otherwise use a
		// file URL derived from the path (a bare "file://"+path is not a valid
		// URL on Windows — see fileURL).
		baseURI := fileURL(abs)
		if m, ok := doc.(map[string]any); ok {
			if id, ok := m["$id"].(string); ok && id != "" {
				baseURI = id
			}
		}
		c := tekuri.NewCompiler()
		for refURL, path := range companions {
			cabs, err := filepath.Abs(path)
			require.NoError(t, err, "resolve companion %s", path)
			cf, err := os.Open(cabs) //nolint:gosec // test-only, reads a vendored schema fixture
			require.NoError(t, err, "open companion %s", path)
			cdoc, err := tekuri.UnmarshalJSON(cf)
			_ = cf.Close()
			require.NoError(t, err, "parse companion %s", path)
			require.NoError(t, c.AddResource(refURL, cdoc), "register companion %s", refURL)
		}
		require.NoError(t, c.AddResource(baseURI, doc), "register schema %s", schemaPath)
		schema, err := c.Compile(baseURI)
		require.NoError(t, err, "compile schema %s", schemaPath)
		return &SchemaValidator{modern: schema}
	}

	// Load from bytes rather than file:// reference loaders: a "file://"+path
	// reference is not a valid URL on Windows (see fileURL), and companions are
	// resolved by their registered $ref URLs regardless of source.
	sl := gojsonschema.NewSchemaLoader()
	for refURL, path := range companions {
		craw, err := os.ReadFile(path) //nolint:gosec // test-only, reads a vendored schema fixture
		require.NoError(t, err, "read companion %s", path)
		require.NoError(t, sl.AddSchema(refURL, gojsonschema.NewBytesLoader(craw)),
			"register companion %s", refURL)
	}
	schema, err := sl.Compile(gojsonschema.NewBytesLoader(raw))
	require.NoError(t, err, "compile schema %s", schemaPath)
	return &SchemaValidator{draft07: schema}
}

// fileURL renders an absolute filesystem path as a valid file:// URL for use as
// a schema compiler base URI on every OS. A bare "file://"+path breaks on
// Windows, where a drive path (D:\a\x.json) parses as host "d" with an invalid
// port; net/url percent-escapes and slash-normalizes it into file:///D:/a/x.json
// instead. Pure string-shape detection (never runtime.GOOS or filepath.ToSlash,
// both OS-dependent) so it is testable on any OS — mirrors the CLI's
// seedURIFromPath.
func fileURL(abs string) string {
	// Backslash is a legal POSIX filename character, so it is treated as a
	// separator only inside the provably-Windows drive and UNC shapes below.
	isDrive := len(abs) >= 2 && abs[1] == ':' &&
		(('a' <= abs[0] && abs[0] <= 'z') || ('A' <= abs[0] && abs[0] <= 'Z'))
	if isDrive {
		// Drive-letter absolute (C:\... or C:/...): the leading slash keeps the
		// drive in the path rather than the authority → file:///C:/...
		return (&url.URL{Scheme: "file", Path: "/" + strings.ReplaceAll(abs, `\`, "/")}).String()
	}
	if strings.HasPrefix(abs, `\\`) {
		// UNC \\host\share\... → file://host/share/...
		slashed := strings.ReplaceAll(abs, `\`, "/")
		host, rest := slashed[2:], "/"
		if i := strings.Index(host, "/"); i >= 0 {
			host, rest = host[:i], host[i:]
		}
		return (&url.URL{Scheme: "file", Host: host, Path: rest}).String()
	}
	// POSIX absolute path: already a valid file path; backslashes here are
	// legal filename characters and are left intact.
	return (&url.URL{Scheme: "file", Path: abs}).String()
}

// schemaIsModern reports whether the schema declares a 2019-09 or 2020-12 draft.
func schemaIsModern(raw []byte) bool {
	var head struct {
		Schema string `json:"$schema"`
	}
	_ = json.Unmarshal(raw, &head)
	return strings.Contains(head.Schema, "2019-09") || strings.Contains(head.Schema, "2020-12")
}

// Validate reports whether doc satisfies the schema, returning the violations
// rather than failing a test. Callers that need to assert a document is
// *invalid* — the corpus tier-B contract — cannot use RequireValid, which fails
// the test on exactly the outcome they are asserting.
func (v *SchemaValidator) Validate(doc []byte) error {
	if v.modern != nil {
		inst, err := tekuri.UnmarshalJSON(bytes.NewReader(doc))
		if err != nil {
			return fmt.Errorf("parse document: %w", err)
		}
		return v.modern.Validate(inst)
	}

	result, err := v.draft07.Validate(gojsonschema.NewBytesLoader(doc))
	if err != nil {
		return fmt.Errorf("schema validation errored: %w", err)
	}
	if result.Valid() {
		return nil
	}
	msgs := make([]string, 0, len(result.Errors()))
	for _, e := range result.Errors() {
		msgs = append(msgs, fmt.Sprintf("%s: %s", e.Field(), e.Description()))
	}
	return errors.New(strings.Join(msgs, "\n"))
}

// RequireValid asserts doc satisfies the schema, reporting every violation on
// failure so a red run pinpoints exactly what is wrong.
func (v *SchemaValidator) RequireValid(t *testing.T, label string, doc []byte) {
	t.Helper()
	if err := v.Validate(doc); err != nil {
		t.Fatalf("%s: document does not satisfy the schema:\n%v", label, err)
	}
}
