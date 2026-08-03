package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hdfvalidators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enrichFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "enrich-fixtures", name))
	require.NoError(t, err)
	return b
}

func enrichDoc(t *testing.T, out []byte) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))
	return doc
}

func rootRefs(t *testing.T, doc map[string]interface{}) []interface{} {
	t.Helper()
	if v, ok := doc["externalReferences"]; ok {
		return v.([]interface{})
	}
	return nil
}

func requirementByID(t *testing.T, doc map[string]interface{}, id string) map[string]interface{} {
	t.Helper()
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

func reqRefs(req map[string]interface{}) []interface{} {
	if v, ok := req["externalReferences"]; ok {
		return v.([]interface{})
	}
	return nil
}

// sourceObjectByCVE independently locates the raw STIX object in the bundle that
// carries the given CVE — the oracle for the lossless-passthrough assertion.
func sourceObjectByCVE(t *testing.T, bundle []byte, cve string) map[string]interface{} {
	t.Helper()
	var b struct {
		Objects []map[string]interface{} `json:"objects"`
	}
	require.NoError(t, json.Unmarshal(bundle, &b))
	for _, o := range b.Objects {
		for _, r := range asRefs(o["external_references"]) {
			if r["source_name"] == "cve" && r["external_id"] == cve {
				return o
			}
		}
	}
	t.Fatalf("no STIX object carries %s", cve)
	return nil
}

func asRefs(v interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	if arr, ok := v.([]interface{}); ok {
		for _, e := range arr {
			if m, ok := e.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func TestEnrichStix_CVEMatchAndRoot(t *testing.T) {
	results := enrichFixture(t, "results-input.json")
	bundle := enrichFixture(t, "poison-ivy-stix21.json")

	out, err := EnrichStix(results, bundle)
	require.NoError(t, err)
	doc := enrichDoc(t, out)

	// Unmatched CVE (CVE-2013-0422) + 6 non-CVE objects → results root.
	assert.Len(t, rootRefs(t, doc), 7, "unmatched CVE + non-CVE objects land on the results root")

	// CVE-2012-0158 STIX vulnerability attaches to the finding with that id.
	req := requirementByID(t, doc, "CVE-2012-0158")
	refs := reqRefs(req)
	require.Len(t, refs, 1, "one STIX ref on the CVE-matched finding")
	ref := refs[0].(map[string]interface{})
	assert.Equal(t, "stix", ref["sourceName"])
	assert.Equal(t, "threat-intel", ref["kind"])
	assert.Equal(t, "vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab34361a2", ref["externalId"])
	assert.Equal(t, "investigate", ref["rel"], "CVE-matched refs are live pivots")

	// Second CVE also matched.
	assert.Len(t, reqRefs(requirementByID(t, doc, "CVE-2009-4324")), 1)

	// A finding with no STIX correlation is left untouched.
	sv := requirementByID(t, doc, "SV-999999")
	assert.Empty(t, reqRefs(sv), "non-matching finding must not be enriched")
}

func TestEnrichStix_LosslessDocument(t *testing.T) {
	results := enrichFixture(t, "results-input.json")
	bundle := enrichFixture(t, "poison-ivy-stix21.json")

	out, err := EnrichStix(results, bundle)
	require.NoError(t, err)
	doc := enrichDoc(t, out)

	ref := reqRefs(requirementByID(t, doc, "CVE-2012-0158"))[0].(map[string]interface{})
	// document is the raw STIX object, byte-for-byte (deep-equal to the source).
	want := sourceObjectByCVE(t, bundle, "CVE-2012-0158")
	assert.Equal(t, want, ref["document"], "document must be the lossless raw STIX object")
}

func TestEnrichStix_UnmatchedCVEToRootAsReference(t *testing.T) {
	out, err := EnrichStix(enrichFixture(t, "results-input.json"), enrichFixture(t, "poison-ivy-stix21.json"))
	require.NoError(t, err)
	doc := enrichDoc(t, out)

	var found map[string]interface{}
	for _, r := range rootRefs(t, doc) {
		ref := r.(map[string]interface{})
		if d, ok := ref["document"].(map[string]interface{}); ok && d["name"] == "CVE-2013-0422" {
			found = ref
		}
	}
	require.NotNil(t, found, "unmatched CVE vulnerability must land on the root")
	assert.Equal(t, "reference", found["rel"], "root-level context uses rel 'reference'")
	assert.Equal(t, "stix", found["sourceName"])
}

func TestEnrichStix_Anchor(t *testing.T) {
	bundle := enrichFixture(t, "poison-ivy-stix21.json")
	out, err := EnrichStix(enrichFixture(t, "results-input.json"), bundle)
	require.NoError(t, err)
	doc := enrichDoc(t, out)

	total := len(rootRefs(t, doc))
	for _, b := range doc["baselines"].([]interface{}) {
		for _, r := range b.(map[string]interface{})["requirements"].([]interface{}) {
			total += len(reqRefs(r.(map[string]interface{})))
		}
	}
	// Ground-truth anchor: exactly one emitted ref per STIX object in the bundle.
	assert.Equal(t, CountJSONItemsUnderKey(t, bundle, "objects"), total)
	assert.Equal(t, 9, total)
}

func TestEnrichStix_AuthorsNoOverrides(t *testing.T) {
	out, err := EnrichStix(enrichFixture(t, "results-input.json"), enrichFixture(t, "poison-ivy-stix21.json"))
	require.NoError(t, err)
	doc := enrichDoc(t, out)

	// Not one override anywhere in the enriched doc — the informational pass is
	// additive to externalReferences[] only. (Counts unconditionally, so it fails
	// even if an override is added under any finding.)
	overrides := 0
	for _, b := range doc["baselines"].([]interface{}) {
		for _, r := range b.(map[string]interface{})["requirements"].([]interface{}) {
			overrides += len(reqRefsUnderKey(r.(map[string]interface{}), "statusOverrides"))
		}
	}
	assert.Equal(t, 0, overrides, "enrich pass must author zero overrides")

	// A CVE-matched finding's status and impact must be untouched (no fabrication).
	matched := requirementByID(t, doc, "CVE-2012-0158")
	assert.Equal(t, 0.9, matched["impact"], "impact must be preserved verbatim")
	results := matched["results"].([]interface{})
	assert.Equal(t, "failed", results[0].(map[string]interface{})["status"], "status must be preserved verbatim")
}

func reqRefsUnderKey(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

func TestEnrichStix_OutputIsSchemaValid(t *testing.T) {
	out, err := EnrichStix(enrichFixture(t, "results-input.json"), enrichFixture(t, "poison-ivy-stix21.json"))
	require.NoError(t, err)
	r := hdfvalidators.ValidateResults(out)
	assert.True(t, r.Valid, r.Error())
}

// TestEnrichStix_Golden compares the enriched output against a committed golden
// shared with the TypeScript pass, guaranteeing Go↔TS parity. Regenerate with
// UPDATE_ENRICH_GOLDEN=1. JSONEq is key-order-independent, so Go's sorted map
// keys and TS's insertion order both satisfy it.
func TestEnrichStix_Golden(t *testing.T) {
	out, err := EnrichStix(enrichFixture(t, "results-input.json"), enrichFixture(t, "poison-ivy-stix21.json"))
	require.NoError(t, err)
	goldenPath := filepath.Join("..", "enrich-fixtures", "results-enriched.golden.json")
	if os.Getenv("UPDATE_ENRICH_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, append(out, '\n'), 0o644))
	}
	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(out))
}

func TestEnrichStix_Errors(t *testing.T) {
	bundle := enrichFixture(t, "poison-ivy-stix21.json")
	results := enrichFixture(t, "results-input.json")

	t.Run("empty results", func(t *testing.T) {
		_, err := EnrichStix([]byte(""), bundle)
		assert.Error(t, err)
	})
	t.Run("invalid bundle JSON", func(t *testing.T) {
		_, err := EnrichStix(results, []byte("not json"))
		assert.Error(t, err)
	})
	t.Run("JSON that is not a STIX bundle", func(t *testing.T) {
		_, err := EnrichStix(results, []byte(`{"type":"something-else","objects":[]}`))
		assert.Error(t, err)
	})
}

func TestEnrichStix_Recompute(t *testing.T) {
	results := enrichFixture(t, "results-with-cvss.json")
	bundle := enrichFixture(t, "poison-ivy-exploited-stix21.json")
	asOf, _ := time.Parse(time.RFC3339, "2099-01-01T00:00:00Z")

	out, err := EnrichStix(results, bundle, EnrichOptions{RecomputeCVSS: true, AsOf: asOf})
	require.NoError(t, err)
	doc := enrichDoc(t, out)

	// CVE-2012-0158: exploited + 3.1 baseVector → inline riskAdjustment authored.
	req := requirementByID(t, doc, "CVE-2012-0158")
	so := reqRefsUnderKey(req, "statusOverrides")
	require.Len(t, so, 1, "riskAdjustment authored on the exploited 3.1 finding")
	ov := so[0].(map[string]interface{})
	assert.Equal(t, "riskAdjustment", ov["type"])
	assert.Equal(t, "2099-01-01T00:00:00Z", ov["appliedAt"])
	assert.Equal(t, "2099-04-01T00:00:00Z", ov["expiresAt"], "AsOf + 90d review horizon")
	assert.InDelta(t, 0.98, ov["impact"].(map[string]interface{})["value"], 1e-9)
	cvss := ov["cvss"].(map[string]interface{})
	assert.Equal(t, "3.1", cvss["version"])
	assert.Equal(t, "E:H", cvss["threatVector"])
	assert.InDelta(t, 9.8, cvss["computedScore"], 1e-9)
	ovRefs := ov["externalReferences"].([]interface{})
	require.Len(t, ovRefs, 1)
	assert.Equal(t, "stix", ovRefs[0].(map[string]interface{})["sourceName"])

	// CVE-2009-4324: exploited but NO base vector → skip (no fabrication).
	assert.Empty(t, reqRefsUnderKey(requirementByID(t, doc, "CVE-2009-4324"), "statusOverrides"))
	// CVE-2013-0422: exploited but 4.0 base vector → skip (deferred to ne8q.8).
	assert.Empty(t, reqRefsUnderKey(requirementByID(t, doc, "CVE-2013-0422"), "statusOverrides"))

	// Output remains schema-valid.
	r := hdfvalidators.ValidateResults(out)
	assert.True(t, r.Valid, r.Error())
}

func TestEnrichStix_RecomputeMultiCVEVulnerability(t *testing.T) {
	// One STIX vulnerability citing TWO CVEs, with one sighting of it: the
	// exploitation signal must reach BOTH findings, not just the last CVE
	// the vulnerability's external_references happened to list.
	results := []byte(`{
	  "generator": { "name": "hdf-converters", "version": "0.0.0" },
	  "baselines": [{
	    "name": "Vulnerability Scan",
	    "checksum": { "algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000" },
	    "requirements": [
	      { "id": "CVE-2024-0001", "title": "first", "descriptions": [{ "label": "default", "data": "d" }], "impact": 0.9, "tags": {},
	        "cvss": [{ "version": "3.1", "id": "CVE-2024-0001", "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8 }],
	        "results": [{ "status": "failed", "codeDesc": "d", "startTime": "2025-01-01T00:00:00Z" }] },
	      { "id": "CVE-2024-0002", "title": "second", "descriptions": [{ "label": "default", "data": "d" }], "impact": 0.9, "tags": {},
	        "cvss": [{ "version": "3.1", "id": "CVE-2024-0002", "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8 }],
	        "results": [{ "status": "failed", "codeDesc": "d", "startTime": "2025-01-01T00:00:00Z" }] }
	    ]
	  }],
	  "statistics": { "duration": 1 },
	  "timestamp": "2025-06-01T00:00:00Z"
	}`)
	bundle := []byte(`{"type":"bundle","id":"bundle--multi","objects":[
	  {"type":"vulnerability","spec_version":"2.1","id":"vulnerability--1","name":"multi",
	   "external_references":[
	     {"source_name":"cve","external_id":"CVE-2024-0001"},
	     {"source_name":"cve","external_id":"CVE-2024-0002"}]},
	  {"type":"sighting","spec_version":"2.1","id":"sighting--1","sighting_of_ref":"vulnerability--1"}
	]}`)
	asOf, _ := time.Parse(time.RFC3339, "2099-01-01T00:00:00Z")

	out, err := EnrichStix(results, bundle, EnrichOptions{RecomputeCVSS: true, AsOf: asOf})
	require.NoError(t, err)
	doc := enrichDoc(t, out)
	require.Len(t, reqRefsUnderKey(requirementByID(t, doc, "CVE-2024-0001"), "statusOverrides"), 1,
		"first cited CVE gets the riskAdjustment")
	require.Len(t, reqRefsUnderKey(requirementByID(t, doc, "CVE-2024-0002"), "statusOverrides"), 1,
		"second cited CVE gets the riskAdjustment")
}

func TestEnrichStix_RecomputeIsOptIn(t *testing.T) {
	// Default (no opts / RecomputeCVSS false) authors NO overrides even with exploitation present.
	out, err := EnrichStix(enrichFixture(t, "results-with-cvss.json"), enrichFixture(t, "poison-ivy-exploited-stix21.json"))
	require.NoError(t, err)
	doc := enrichDoc(t, out)
	for _, id := range []string{"CVE-2012-0158", "CVE-2009-4324", "CVE-2013-0422"} {
		assert.Empty(t, reqRefsUnderKey(requirementByID(t, doc, id), "statusOverrides"), id)
	}
}

func TestEnrichStix_IdlessObjectStaysSchemaValid(t *testing.T) {
	results := enrichFixture(t, "results-input.json")
	// STIX objects with no id — a named campaign, a nameless note, and a
	// type-less object (exercises each description-fallback branch).
	bundle := []byte(`{"type":"bundle","id":"bundle--1","objects":[` +
		`{"type":"campaign","spec_version":"2.1","name":"th3bug"},` +
		`{"type":"note","spec_version":"2.1"},` +
		`{"spec_version":"2.1","marker":"typeless"}]}`)
	out, err := EnrichStix(results, bundle)
	require.NoError(t, err)

	// Every emitted reference must satisfy External_Reference's anyOf
	// (externalId/href/description), even when the STIX object carries no id.
	r := hdfvalidators.ValidateResults(out)
	assert.True(t, r.Valid, r.Error())

	refs := reqRefsUnderKey(enrichDoc(t, out), "externalReferences")
	find := func(field, val string) map[string]interface{} {
		for _, ri := range refs {
			ref := ri.(map[string]interface{})
			if d, ok := ref["document"].(map[string]interface{}); ok && d[field] == val {
				return ref
			}
		}
		return nil
	}
	campaign := find("name", "th3bug")
	require.NotNil(t, campaign)
	assert.Nil(t, campaign["externalId"])
	assert.Equal(t, "th3bug", campaign["description"], "name is the description fallback")
	note := find("type", "note")
	require.NotNil(t, note)
	assert.Equal(t, "STIX note object", note["description"], "type-derived fallback when nameless")
	typeless := find("marker", "typeless")
	require.NotNil(t, typeless)
	assert.Equal(t, "STIX object", typeless["description"], "generic fallback when id/name/type all absent")
}
