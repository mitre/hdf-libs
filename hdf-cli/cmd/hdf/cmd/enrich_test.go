package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
