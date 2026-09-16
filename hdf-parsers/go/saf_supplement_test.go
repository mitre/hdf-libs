package hdfparsers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validV3WithExtra returns a minimal schema-valid v3 results doc with the given
// extra top-level keys spliced in (e.g. a legacy SAF target/passthrough). Per the
// schema those keys are unevaluated (unevaluatedProperties:false), but the Go
// validator (gojsonschema, draft-07) does not enforce that keyword, so they pass
// Go validation and are lost at the typed unmarshal instead; normalization is what
// makes the values survive.
func validV3WithExtra(t *testing.T, extra map[string]any) []byte {
	t.Helper()
	doc := map[string]any{
		"timestamp":  "2026-01-01T00:00:00Z",
		"generator":  map[string]any{"name": "t", "version": "0.0.1"},
		"statistics": map[string]any{"duration": 0.1},
		"baselines": []any{map[string]any{
			"name":            "B",
			"resultsChecksum": map[string]any{"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
			"requirements": []any{map[string]any{
				"id": "x", "title": "t", "impact": 0.0, "tags": map[string]any{},
				"descriptions": []any{map[string]any{"label": "default", "data": "d"}},
				"results":      []any{map[string]any{"status": "passed", "codeDesc": "d", "startTime": "2026-01-01T00:00:00Z"}},
			}},
		}},
	}
	for k, v := range extra {
		doc[k] = v
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return b
}

func firstComponent(t *testing.T, out []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	_, hasTarget := doc["target"]
	assert.False(t, hasTarget, "top-level target must be removed after normalization")
	comps, ok := doc["components"].([]any)
	require.True(t, ok, "components[] must be present")
	require.NotEmpty(t, comps)
	return comps[0].(map[string]any)
}

// TestNormalizeSAFSupplement_TargetBecomesComponent is the card's first failing
// test: a legacy top-level target becomes a components[] cloudAccount entry, and
// the normalized document validates as HDF results.
func TestNormalizeSAFSupplement_TargetBecomesComponent(t *testing.T) {
	in := validV3WithExtra(t, map[string]any{
		"target": map[string]any{"id": "prod-account", "type": "cloudAccount", "boundary": "sparc"},
	})
	// NOTE: the Go validator (gojsonschema, draft-07) ignores the schema's
	// unevaluatedProperties:false, so a top-level `target` is not *rejected* here —
	// it is silently dropped at the typed unmarshal. The TS validator (ajv) does
	// enforce it. Either way the value must survive: normalization is what makes it.
	out, warnings := NormalizeSAFSupplement(in)

	c := firstComponent(t, out)
	assert.Equal(t, "cloudAccount", c["type"])
	assert.Equal(t, "prod-account", c["name"])
	assert.Equal(t, "prod-account", c["accountId"])
	labels, _ := c["labels"].(map[string]any)
	require.NotNil(t, labels)
	assert.Equal(t, "sparc", labels["boundary"], "boundary maps to a label")
	assert.True(t, validators.ValidateResults(out).Valid, "normalized doc must be schema-valid v3")
	assert.NotEmpty(t, warnings, "a deprecation warning is returned for the rewritten target")
}

// TestNormalizeSAFSupplement_PassthroughBecomesExtensions: legacy top-level
// passthrough moves under extensions.passthrough, preserving its content.
func TestNormalizeSAFSupplement_PassthroughBecomesExtensions(t *testing.T) {
	in := validV3WithExtra(t, map[string]any{
		"passthrough": map[string]any{"audit": map[string]any{"runId": "r-123"}},
	})
	out, warnings := NormalizeSAFSupplement(in)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	_, hasPassthrough := doc["passthrough"]
	assert.False(t, hasPassthrough, "top-level passthrough must be removed")
	ext, ok := doc["extensions"].(map[string]any)
	require.True(t, ok, "extensions must be present")
	pt, ok := ext["passthrough"].(map[string]any)
	require.True(t, ok, "passthrough carried under extensions.passthrough")
	audit, _ := pt["audit"].(map[string]any)
	require.NotNil(t, audit)
	assert.Equal(t, "r-123", audit["runId"])
	assert.True(t, validators.ValidateResults(out).Valid)
	assert.NotEmpty(t, warnings)
}

// TestNormalizeSAFSupplement_PassthroughMergesWithoutClobbering: when extensions
// already carries other keys, passthrough is added alongside them — existing
// extension data is never clobbered.
func TestNormalizeSAFSupplement_PassthroughMergesWithoutClobbering(t *testing.T) {
	in := validV3WithExtra(t, map[string]any{
		"extensions":  map[string]any{"foo": "bar"},
		"passthrough": map[string]any{"audit": map[string]any{"runId": "r-1"}},
	})
	out, _ := NormalizeSAFSupplement(in)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	ext := doc["extensions"].(map[string]any)
	assert.Equal(t, "bar", ext["foo"], "existing extensions key must be preserved")
	pt := ext["passthrough"].(map[string]any)
	audit := pt["audit"].(map[string]any)
	assert.Equal(t, "r-1", audit["runId"], "passthrough added alongside existing extensions")
}

// TestNormalizeSAFSupplement_NoLegacyKeysByteIdentical: a doc with no legacy keys
// passes through byte-identical (idempotent, narrow) and yields no warnings.
func TestNormalizeSAFSupplement_NoLegacyKeysByteIdentical(t *testing.T) {
	in := validV3WithExtra(t, nil)
	out, warnings := NormalizeSAFSupplement(in)
	assert.Equal(t, string(in), string(out), "no legacy keys → byte-identical passthrough")
	assert.Empty(t, warnings)
}

// TestNormalizeSAFSupplement_MergesIntoExistingComponents: a target whose
// name/type already matches an existing component merges (adds the label) rather
// than duplicating.
func TestNormalizeSAFSupplement_MergesIntoExistingComponents(t *testing.T) {
	in := validV3WithExtra(t, map[string]any{
		"components": []any{map[string]any{"name": "prod-account", "type": "cloudAccount"}},
		"target":     map[string]any{"id": "prod-account", "type": "cloudAccount", "boundary": "sparc"},
	})
	out, _ := NormalizeSAFSupplement(in)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	comps := doc["components"].([]any)
	assert.Len(t, comps, 1, "matching component must be merged, not duplicated")
	c := comps[0].(map[string]any)
	labels := c["labels"].(map[string]any)
	assert.Equal(t, "sparc", labels["boundary"])
}

// TestNormalizeSAFSupplement_UnmappedTypeWarnsAndLeaves: a target whose type is
// not a valid component type is warned and left in place for the schema to
// reject — never guessed into a wrong type.
func TestNormalizeSAFSupplement_UnmappedTypeWarnsAndLeaves(t *testing.T) {
	in := validV3WithExtra(t, map[string]any{
		"target": map[string]any{"id": "x", "type": "not-a-real-type"},
	})
	out, warnings := NormalizeSAFSupplement(in)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	_, hasTarget := doc["target"]
	assert.True(t, hasTarget, "an unmappable target is left for the schema to reject, not silently dropped")
	assert.NotEmpty(t, warnings, "a warning names the unmapped type")
}

// TestParseResults_AcceptsSAFSupplementedDoc covers camfd: ParseResults runs the
// normalizer before validation, so a doc carrying legacy top-level target/passthrough
// parses with target as a components[] entry and passthrough under extensions, and
// the deprecation warnings surface on the result.
func TestParseResults_AcceptsSAFSupplementedDoc(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("..", "testdata", "saf-supplement", "legacy-in.json"))
	require.NoError(t, err)

	r := ParseResults(in)
	require.True(t, r.Success, "SAF-supplemented doc must parse: %s", r.Error)
	require.NotNil(t, r.Data)

	found := false
	for _, c := range r.Data.Components {
		if c.Name == "prod-account" && string(c.Type) == "cloudAccount" {
			found = true
		}
	}
	assert.True(t, found, "legacy target must be normalized into a components[] entry before parse")
	assert.NotEmpty(t, r.Warnings, "the deprecation warning must surface on the parse result")
}

// TestNormalizeSAFSupplement_SharedFixtureParity pins Go against the shared
// legacy-in/v3-out fixture pair the TS suite also reads, so both languages
// normalize the same input to the same v3 document (deep-equal; JSON key order
// differs across languages so this compares parsed structure, not bytes).
func TestNormalizeSAFSupplement_SharedFixtureParity(t *testing.T) {
	dir := filepath.Join("..", "testdata", "saf-supplement")
	in, err := os.ReadFile(filepath.Join(dir, "legacy-in.json"))
	require.NoError(t, err)
	expected, err := os.ReadFile(filepath.Join(dir, "v3-out.json"))
	require.NoError(t, err)

	out, _ := NormalizeSAFSupplement(in)

	var got, want any
	require.NoError(t, json.Unmarshal(out, &got))
	require.NoError(t, json.Unmarshal(expected, &want))
	assert.Equal(t, want, got, "normalized output must match the shared v3-out fixture")
	assert.True(t, validators.ValidateResults(out).Valid, "shared fixture normalizes to schema-valid v3")
}
