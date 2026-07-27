package hdfvalidators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// resultsWith wraps an externalReferences JSON fragment into an otherwise-valid
// HDF Results document so the test isolates External_Reference validation.
func resultsWithExtRefs(externalRefsJSON string) []byte {
	return []byte(`{
		"baselines": [{
			"name": "Test Baseline",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"descriptions": [{ "label": "default", "data": "d" }],
				"impact": 0.5,
				"tags": {},
				"results": [{ "status": "passed", "codeDesc": "ok", "startTime": "2025-01-01T00:00:00Z" }]
			}]
		}],
		"components": [],
		"statistics": {},
		"externalReferences": ` + externalRefsJSON + `
	}`)
}

func TestValidateResults_ExternalReferences(t *testing.T) {
	t.Run("by-identity ref (sourceName + externalId) validates", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "cve", "externalId": "CVE-2021-44228" }]`))
		assert.True(t, r.Valid, r.Error())
	})

	t.Run("by-locator ref (sourceName + href with #fragment) validates", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "stix", "href": "#bundle--1" }]`))
		assert.True(t, r.Valid, r.Error())
	})

	t.Run("id AND href together validates (anyOf, not oneOf)", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "cve", "externalId": "CVE-2021-44228", "href": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "rel": "definition" }]`))
		assert.True(t, r.Valid, r.Error())
	})

	t.Run("missing sourceName is rejected", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "externalId": "CVE-2021-44228" }]`))
		assert.False(t, r.Valid, "a ref with no sourceName must be rejected")
	})

	t.Run("sourceName with none of externalId/href/description is rejected", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "cve" }]`))
		assert.False(t, r.Valid, "a ref with sourceName but no id/href/description must be rejected")
	})
}

// --- DRY-inheritance carriers: externalReferences must be valid (and enforce
// the anyOf/sourceName rule) on carriers that inherit External_Reference via
// allOf Requirement_Core / Baseline_Metadata, plus Standalone_Override. These
// guard the unevaluatedProperties+allOf interaction that AC-verify flagged. ---

const validRef = `[{ "sourceName": "cve", "externalId": "CVE-2021-44228" }]`
const badRef = `[{ "externalId": "no-source" }]`

func baselineWithExtRefs(rootRefs, reqRefs string) []byte {
	return []byte(`{
		"name": "B", "title": "T", "version": "1.0.0",
		"checksum": { "algorithm": "sha256", "value": "abc" },
		"externalReferences": ` + rootRefs + `,
		"requirements": [{ "id": "R1", "title": "t", "descriptions": [{ "label": "default", "data": "d" }], "impact": 0.5, "tags": {}, "externalReferences": ` + reqRefs + ` }]
	}`)
}

func resultsSubCarrier(baselineRefs, reqRefs string) []byte {
	return []byte(`{
		"baselines": [{
			"name": "B", "checksum": { "algorithm": "sha256", "value": "abc" },
			"externalReferences": ` + baselineRefs + `,
			"requirements": [{ "id": "R1", "descriptions": [{ "label": "default", "data": "d" }], "impact": 0.5, "tags": {}, "externalReferences": ` + reqRefs + `, "results": [{ "status": "passed", "codeDesc": "ok", "startTime": "2025-01-01T00:00:00Z" }] }]
		}],
		"components": [], "statistics": {}
	}`)
}

func amendmentsWithExtRefs(refs string) []byte {
	return []byte(`{
		"name": "A",
		"overrides": [{
			"type": "riskAdjustment", "requirementId": "CVE-2021-44228", "baselineRef": "B",
			"impact": { "value": 0.5 }, "reason": "r",
			"appliedBy": { "type": "email", "identifier": "a@b.gov" },
			"appliedAt": "2026-04-14T10:00:00Z", "expiresAt": "2026-10-14T00:00:00Z",
			"externalReferences": ` + refs + `
		}]
	}`)
}

func TestExternalReferences_BaselineCarriers(t *testing.T) {
	t.Run("baseline root + Requirement_Core accept valid refs", func(t *testing.T) {
		assert.True(t, ValidateBaseline(baselineWithExtRefs(validRef, validRef)).Valid)
	})
	t.Run("baseline root rejects malformed ref", func(t *testing.T) {
		assert.False(t, ValidateBaseline(baselineWithExtRefs(badRef, validRef)).Valid)
	})
	t.Run("baseline Requirement_Core rejects malformed ref", func(t *testing.T) {
		assert.False(t, ValidateBaseline(baselineWithExtRefs(validRef, badRef)).Valid)
	})
}

func TestExternalReferences_ResultsSubCarriers(t *testing.T) {
	t.Run("Evaluated_Baseline + Evaluated_Requirement accept valid refs", func(t *testing.T) {
		assert.True(t, ValidateResults(resultsSubCarrier(validRef, validRef)).Valid)
	})
	t.Run("Evaluated_Baseline rejects malformed ref", func(t *testing.T) {
		assert.False(t, ValidateResults(resultsSubCarrier(badRef, validRef)).Valid)
	})
	t.Run("Evaluated_Requirement rejects malformed ref", func(t *testing.T) {
		assert.False(t, ValidateResults(resultsSubCarrier(validRef, badRef)).Valid)
	})
}

func TestExternalReferences_StandaloneOverride(t *testing.T) {
	t.Run("Standalone_Override accepts valid ref", func(t *testing.T) {
		assert.True(t, ValidateAmendments(amendmentsWithExtRefs(validRef)).Valid)
	})
	t.Run("Standalone_Override rejects malformed ref", func(t *testing.T) {
		assert.False(t, ValidateAmendments(amendmentsWithExtRefs(badRef)).Valid)
	})
}

// --- Phase 1b: enrichment envelope (document + open kind) + inline
// Status_Override carrier for the E:A riskAdjustment. ---

func TestExternalReferences_EnvelopeDocumentKind(t *testing.T) {
	t.Run("embedded document + kind validates", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "stix", "externalId": "threat-actor--9b7e", "kind": "threat-intel", "document": { "type": "threat-actor", "id": "threat-actor--9b7e", "name": "APT-X", "spec_version": "2.1" } }]`))
		assert.True(t, r.Valid, r.Error())
	})
	t.Run("document composed with href + externalId validates", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "stix", "externalId": "vulnerability--1", "href": "https://cti.example.org/bundles/log4shell.json#vulnerability--1", "kind": "threat-intel", "document": { "type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2021-44228" } }]`))
		assert.True(t, r.Valid, r.Error())
	})
	t.Run("open kind value not in the starter vocabulary validates", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "sourceName": "acme-feed", "externalId": "x1", "kind": "x-vendor-custom" }]`))
		assert.True(t, r.Valid, r.Error())
	})
	t.Run("embedded document with no sourceName is rejected", func(t *testing.T) {
		r := ValidateResults(resultsWithExtRefs(`[{ "kind": "threat-intel", "document": { "type": "x" } }]`))
		assert.False(t, r.Valid, "a ref with a document but no sourceName must be rejected")
	})
}

// resultsWithInlineOverride wraps externalReferences into a Status_Override on
// Evaluated_Requirement.overrides[] — the carrier the enrich pass writes.
func resultsWithInlineOverride(refs string) []byte {
	return []byte(`{
		"baselines": [{
			"name": "B", "checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "CVE-2021-44228", "descriptions": [{ "label": "default", "data": "d" }], "impact": 0.5, "tags": {},
				"results": [{ "status": "failed", "codeDesc": "x", "startTime": "2025-01-01T00:00:00Z" }],
				"statusOverrides": [{
					"type": "riskAdjustment", "reason": "exploited in the wild (STIX)",
					"impact": { "value": 0.9 },
					"appliedBy": { "type": "email", "identifier": "a@b.gov" },
					"appliedAt": "2026-04-14T10:00:00Z", "expiresAt": "2026-10-14T00:00:00Z",
					"externalReferences": ` + refs + `
				}]
			}]
		}],
		"components": [], "statistics": {}
	}`)
}

func TestExternalReferences_InlineStatusOverride(t *testing.T) {
	t.Run("inline Status_Override accepts valid ref", func(t *testing.T) {
		assert.True(t, ValidateResults(resultsWithInlineOverride(validRef)).Valid)
	})
	t.Run("inline Status_Override rejects malformed ref", func(t *testing.T) {
		assert.False(t, ValidateResults(resultsWithInlineOverride(badRef)).Valid)
	})
}
