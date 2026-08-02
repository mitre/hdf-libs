package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrichFixturePath resolves a committed shared enrich fixture (the real OASIS
// Poison Ivy bundle + its paired results doc) from the sibling hdf-converters package.
func enrichFixturePath(name string) string {
	return filepath.Join("..", "..", "..", "..", "hdf-converters", "shared", "enrich-fixtures", name)
}

func findEnrichedReq(t *testing.T, data []byte, id string) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	for _, b := range doc["baselines"].([]interface{}) {
		for _, r := range b.(map[string]interface{})["requirements"].([]interface{}) {
			req := r.(map[string]interface{})
			if req["id"] == id {
				return req
			}
		}
	}
	t.Fatalf("requirement %q not found", id)
	return nil
}

func TestEnrichCmd_AutoDetectSTIXToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"-o", out)
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "results", detectHDFDocumentType(data), "output is an HDF results doc")

	// Enrichment landed: the CVE-2012-0158 finding carries the matching STIX ref.
	refs := findEnrichedReq(t, data, "CVE-2012-0158")["externalReferences"].([]interface{})
	require.Len(t, refs, 1)
	ref := refs[0].(map[string]interface{})
	assert.Equal(t, "stix", ref["sourceName"])
	assert.Equal(t, "threat-intel", ref["kind"])
	assert.Equal(t, "vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab34361a2", ref["externalId"])
}

func TestEnrichCmd_OutputValidates(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"-o", out)
	require.NoError(t, err)

	stdout, _, verr := executeCommand("validate", out)
	require.NoError(t, verr)
	assert.Contains(t, stdout, "valid HDF results")
}

func TestEnrichCmd_FromStixAssert(t *testing.T) {
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"--from", "stix")
	require.NoError(t, err)
}

func TestEnrichCmd_Stdout(t *testing.T) {
	stdout, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"))
	require.NoError(t, err)
	assert.Contains(t, stdout, `"sourceName": "stix"`)
}

func TestEnrichCmd_NoMisroute(t *testing.T) {
	// A results doc is not a STIX bundle — auto-detect must fail, not misroute.
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("results-input.json"))
	require.Error(t, err)

	// --from stix asserted on a non-bundle → error (assert-then-detect, no force-parse).
	_, _, err2 := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("results-input.json"),
		"--from", "stix")
	require.Error(t, err2)
}

func TestEnrichCmd_UnsupportedFrom(t *testing.T) {
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"--from", "bogus")
	require.Error(t, err)
}

func TestEnrichCmd_ResultsPositionalMustBeResults(t *testing.T) {
	// First positional must be a results doc; passing the bundle there → error.
	_, _, err := executeCommand("enrich",
		enrichFixturePath("poison-ivy-stix21.json"),
		enrichFixturePath("poison-ivy-stix21.json"))
	require.Error(t, err)
}

func TestEnrichCmd_RejectsSchemaInvalidResults(t *testing.T) {
	// A doc that sniffs as results (has a baselines key) but is not valid HDF
	// must be rejected at the boundary, matching the events commands.
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"baselines":[{"bogus":true}]}`), 0o600))
	_, _, err := executeCommand("enrich", bad, enrichFixturePath("poison-ivy-stix21.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid hdf-results document")
}

func TestEnrichCmd_Recompute(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-with-cvss.json"),
		enrichFixturePath("poison-ivy-exploited-stix21.json"),
		"--recompute-cvss", "-o", out)
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	// Output is schema-valid.
	stdout, _, verr := executeCommand("validate", out)
	require.NoError(t, verr)
	assert.Contains(t, stdout, "valid HDF results")

	// End-to-end: the authored inline riskAdjustment carries the recomputed
	// impact and a not-yet-expired review horizon, so any downstream
	// effective-impact resolver will surface it.
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	var req hdf.EvaluatedRequirement
	found := false
	for _, b := range results.Baselines {
		for _, r := range b.Requirements {
			if r.ID == "CVE-2012-0158" {
				req = r
				found = true
			}
		}
	}
	require.True(t, found, "CVE-2012-0158 finding present")
	require.Len(t, req.StatusOverrides, 1, "riskAdjustment authored")

	authored := req.StatusOverrides[0]
	require.NotNil(t, authored.Impact, "riskAdjustment carries an impact value")
	assert.InDelta(t, 0.98, authored.Impact.Value, 1e-9, "E:H recompute of the 9.8 base vector → impact 0.98")
	assert.True(t, authored.ExpiresAt.After(time.Now()), "review horizon is in the future")
}
