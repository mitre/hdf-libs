package hdftooscalsar

import (
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// arSchema loads the vendored NIST OSCAL v1.1.2 Assessment Results JSON Schema.
// The converter self-declares "oscal-version": "1.1.2", so its output must
// validate against exactly that schema. See ../schemas/PROVENANCE.md.
func arSchema(t *testing.T) *gojsonschema.Schema {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-sar", "schemas",
		"oscal_assessment-results_schema-v1.1.2.json")
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	schema, err := gojsonschema.NewSchema(gojsonschema.NewReferenceLoader("file://" + abs))
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
