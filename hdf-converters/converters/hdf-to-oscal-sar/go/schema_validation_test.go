package hdftooscalsar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// arSchema loads the vendored NIST OSCAL v1.1.2 Assessment Results JSON Schema.
// The converter self-declares "oscal-version": "1.1.2", so its output must
// validate against exactly that schema. See ../schemas/PROVENANCE.md.
//
// The schema is read as bytes rather than via a file:// reference loader: a
// Windows absolute path ("D:\...") produces a malformed file:// URI and fails
// on windows-latest CI. NewBytesLoader sidesteps URI parsing entirely.
func arSchema(t *testing.T) *gojsonschema.Schema {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-sar", "schemas",
		"oscal_assessment-results_schema-v1.1.2.json")
	schemaBytes, err := os.ReadFile(path)
	require.NoError(t, err, "read OSCAL AR schema")
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
	require.NoError(t, err, "load OSCAL AR schema")
	return schema
}

// requireValidAR converts input and asserts the output validates against the
// NIST OSCAL v1.1.2 AR schema, reporting every schema violation on failure.
func requireValidAR(t *testing.T, schema *gojsonschema.Schema, label string, input []byte) {
	t.Helper()
	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err, "%s: conversion failed", label)

	result, err := schema.Validate(gojsonschema.NewBytesLoader(out))
	require.NoError(t, err, "%s: schema validation errored", label)
	if !result.Valid() {
		for _, e := range result.Errors() {
			t.Errorf("%s: %s: %s", label, e.Field(), e.Description())
		}
		t.Fatalf("%s: output is not valid OSCAL Assessment Results v1.1.2", label)
	}
}

// TestConvertHDFToOSCALSAR_SchemaValid gates the converter output on the NIST
// OSCAL v1.1.2 AR schema. The worstCase input is built to exercise every defect
// from GitHub #184: missing reviewed-controls, missing finding.description
// (empty descriptions), missing characterization.origin (impact > 0), and an
// empty-string prop value (empty code).
func TestConvertHDFToOSCALSAR_SchemaValid(t *testing.T) {
	schema := arSchema(t)

	// Modern HDF crafted to trigger all four #184 defects at once.
	worstCase := []byte(`{
		"baselines": [{
			"name": "worst-case",
			"requirements": [{
				"id": "AC-3", "impact": 0.5,
				"tags": { "nist": ["AC-3"] },
				"descriptions": [],
				"code": "",
				"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-06-01T00:00:00Z" }]
			}]
		}]
	}`)

	cases := []struct {
		label string
		input []byte
	}{
		{"worst-case (all four defects)", worstCase},
		{"shared minimal fixture", fixtures.Results.Minimal},
		{"minimal passed", minimalHDFResults(hdf.Passed)},
		{"minimal failed", minimalHDFResults(hdf.Failed)},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			requireValidAR(t, schema, tc.label, tc.input)
		})
	}
}

// TestConvertHDFToOSCALSAR_OriginActorsResolve asserts referential integrity
// beyond JSON-schema validity (GH #184 follow-up, bead d1xo): every
// characterization.origin.actors[].actor-uuid must resolve to a party defined
// in the same document — no dangling references — and the tool must be a single
// consistent party across the whole document.
func TestConvertHDFToOSCALSAR_OriginActorsResolve(t *testing.T) {
	withTool := []byte(`{
		"tool": { "name": "InSpec", "version": "5.22.65", "format": "exec-json" },
		"baselines": [
			{ "name": "b1", "requirements": [
				{ "id": "AC-3", "impact": 0.5, "tags": { "nist": ["AC-3"] },
				  "results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-06-01T00:00:00Z" }] }
			]},
			{ "name": "b2", "requirements": [
				{ "id": "AU-2", "impact": 0.7, "tags": { "nist": ["AU-2"] },
				  "results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-06-01T00:00:00Z" }] }
			]}
		]
	}`)

	cases := []struct {
		label string
		input []byte
	}{
		{"tool identity across two baselines", withTool},
		{"shared minimal fixture", fixtures.Results.Minimal},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			out, err := ConvertHDFToOSCALSAR(tc.input, "1.0.0")
			require.NoError(t, err)

			var doc struct {
				AssessmentResults oscal.AssessmentResults `json:"assessment-results"`
			}
			require.NoError(t, json.Unmarshal(out, &doc))

			definedParties := map[string]bool{}
			for _, p := range doc.AssessmentResults.Metadata.Parties {
				definedParties[p.UUID] = true
			}

			actorUUIDs := map[string]bool{}
			for _, r := range doc.AssessmentResults.Results {
				for _, risk := range r.Risks {
					for _, c := range risk.Characterizations {
						if c.Origin == nil {
							continue
						}
						for _, a := range c.Origin.Actors {
							require.NotEmpty(t, a.ActorID, "actor-uuid must not be empty")
							require.Truef(t, definedParties[a.ActorID],
								"actor-uuid %q does not resolve to a defined party", a.ActorID)
							actorUUIDs[a.ActorID] = true
						}
					}
				}
			}

			require.NotEmpty(t, actorUUIDs, "expected at least one characterization origin actor")
			require.Lenf(t, actorUUIDs, 1,
				"expected one consistent tool party across the document, got %d distinct actor-uuids", len(actorUUIDs))
		})
	}
}
