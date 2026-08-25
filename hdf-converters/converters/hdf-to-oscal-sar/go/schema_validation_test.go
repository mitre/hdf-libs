package hdftooscalsar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go"
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

// corpusExemptions lists, with an owner, every corpus case this converter does
// not yet satisfy. An exemption without a card that removes it is a hole, so
// each entry names one.
//
// The MustNotCorrupt contract removed the exemptions this converter previously
// needed for nested-invalid input: it converts those into schema-valid output,
// which that contract permits. The one remaining exemption is a genuine gap in
// what OSCAL can express, not a converter defect.
var corpusExemptions = map[string]string{
	"zero-baselines": "hdf-libs-wq3u: baselines currently has no minItems, so an empty assessment is legal HDF that OSCAL cannot represent — this converter rejects it deliberately",
}

func corpusMinusExemptions(t *testing.T) []shared.CorpusCase {
	t.Helper()
	all := shared.ResultsCorpus()
	kept := make([]shared.CorpusCase, 0, len(all))
	for _, c := range all {
		if reason, skipped := corpusExemptions[c.Name]; skipped {
			t.Logf("corpus case %q exempted — %s", c.Name, reason)
			continue
		}
		kept = append(kept, c)
	}
	require.NotEmpty(t, kept, "every case exempted — the run would prove nothing")
	return kept
}

// TestConvertHDFToOSCALSAR_AdversarialCorpus holds this converter to all three
// contracts, minus the two documented exemptions above.
func TestConvertHDFToOSCALSAR_AdversarialCorpus(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-sar", "schemas", "oscal_assessment-results_schema-v1.1.2.json"))

	shared.RunSchemaCorpus(t, v, corpusMinusExemptions(t), func(in []byte) ([]byte, error) {
		return ConvertHDFToOSCALSAR(in, "1.0.0")
	})
}

// TestConvertHDFToOSCALSAR_RejectsZeroBaselines pins the converter-specific
// constraint the shared guard cannot express: the guard checks top-level shape,
// not the full HDF schema, and it accepts an empty baselines array because
// hdf-results puts no minItems on it. OSCAL requires at least one result, so
// emitting "results": [] would exit 0 with a document the target schema rejects
// — the silent failure this epic exists to remove.
func TestConvertHDFToOSCALSAR_RejectsZeroBaselines(t *testing.T) {
	_, err := ConvertHDFToOSCALSAR([]byte(`{"baselines":[]}`), "1.0.0")
	require.Error(t, err, "OSCAL requires results with minItems 1; an empty assessment has none")
	require.Contains(t, err.Error(), "hdf-to-oscal-sar: ")
}

// TestConvertHDFToOSCALSAR_ResultWithoutRisksIsValid pins the omitempty
// alignment between the two languages. OSCAL puts minItems 1 on a result's
// findings, observations and risks, so an empty array is invalid where absence
// is fine. TypeScript emitted [] for all three where Go omits them, which made a
// baseline whose requirements produce no risks fail the schema on one side only.
func TestConvertHDFToOSCALSAR_ResultWithoutRisksIsValid(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-sar", "schemas", "oscal_assessment-results_schema-v1.1.2.json"))

	// impact 0 produces a finding but no risk.
	input, err := json.Marshal(testhdf.Results(testhdf.Req("AC-1",
		testhdf.Impact(0), testhdf.Status(hdf.Passed))))
	require.NoError(t, err)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	require.NoError(t, v.Validate(out), "a result with no risks must still satisfy the schema")
	require.NotContains(t, string(out), `"risks": []`, "an empty risks array violates minItems 1")
}

// TestConvertHDFToOSCALSAR_ResultWithoutObservationsIsValid covers the second
// field of the same omitempty alignment. Unlike the risks case this is NOT
// reachable from schema-valid HDF — Evaluated_Requirement requires results with
// minItems 1 — so the input below is deliberately schema-invalid and the branch
// is defence-in-depth: the shared guard checks top-level shape only, so an
// upstream producer that skips validation can still reach it. Pinned separately
// from the risks case because an empty observations array is a distinct code
// path that a risks-only test leaves uncovered.
func TestConvertHDFToOSCALSAR_ResultWithoutObservationsIsValid(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-sar", "schemas", "oscal_assessment-results_schema-v1.1.2.json"))

	req := testhdf.Req("AC-1", testhdf.Impact(0))
	req.Results = nil
	input, err := json.Marshal(testhdf.Results(req))
	require.NoError(t, err)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	require.NoError(t, v.Validate(out), "a result with no observations must still satisfy the schema")
	require.NotContains(t, string(out), `"observations": []`, "an empty observations array violates minItems 1")
}

// TestConvertHDFToOSCALSAR_OmitsFindingWithoutControlID pins the choice made for
// a requirement carrying no id. OSCAL types finding-target.target-id as a token,
// so an empty one fails the pattern and the whole document with it.
//
// The finding is dropped rather than given a derived identifier: an index or a
// UUID would satisfy the pattern while manufacturing traceability the source
// never had, and a title is prose, not an identifier. Dropping loses a finding
// the source reported, which is the honest cost — HDF requires an id, so this
// input is already invalid and the loss is attributable to the producer.
func TestConvertHDFToOSCALSAR_OmitsFindingWithoutControlID(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-sar", "schemas", "oscal_assessment-results_schema-v1.1.2.json"))

	// One requirement with an id, one without: the identified finding survives
	// and the anonymous one is dropped, so this proves omission is targeted
	// rather than the whole baseline being discarded.
	input := []byte(`{"baselines":[{"name":"b","requirements":[` +
		`{"impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]},` +
		`{"id":"AC-1","impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}` +
		`]}]}`)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	require.NoError(t, v.Validate(out), "an empty target-id fails the OSCAL token pattern")

	var doc struct {
		AR struct {
			Results []struct {
				Findings []struct {
					Target struct {
						TargetID string `json:"target-id"`
					} `json:"target"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.AR.Results[0].Findings, 1, "only the identified requirement yields a finding")
	require.Equal(t, "ac-1", doc.AR.Results[0].Findings[0].Target.TargetID)
}

// TestConvertHDFToOSCALSAR_NonTokenRequirementIDs is the general case card .17
// left open. OSCAL types target-id as a token, and a requirement id only happens
// to satisfy that pattern when the source tool numbers its rules the way NIST
// does. Measured across this repo's real fixtures, 46% of requirement ids do
// not (57% of the distinct ids): package-style ids carrying '/', CIS control numbers starting with a
// digit, advisory ids carrying ':'. Each produced a document the target schema
// rejects, from perfectly valid HDF, at exit 0.
func TestConvertHDFToOSCALSAR_NonTokenRequirementIDs(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-sar", "schemas", "oscal_assessment-results_schema-v1.1.2.json"))

	for _, id := range []string{
		"AC-1",                                // already token-shaped: must be untouched
		"V-38497",                             // ditto
		"1.1",                                 // CIS: leading digit
		"10180",                               // Nessus plugin id
		"CVE-2018-25032/ruby:nokogiri/1.10.9", // package-style, the commonest shape
		"RHSA-2023:7205/nodejs/1:18.20.4-1",   // advisory id
		"CM-2 (1)",                            // spaces and parentheses
		"  AC-2  ",                            // padded: OSCAL's StringDatatype forbids it in the prop
		"café-1",                              // token-valid under \p{L}, but outside the ASCII kept set
	} {
		t.Run(id, func(t *testing.T) {
			input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":` +
				mustQuote(id) + `,"impact":0,"tags":{},` +
				`"descriptions":[{"label":"default","data":"d"}],` +
				`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

			out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
			require.NoError(t, err)
			require.NoError(t, v.Validate(out),
				"a requirement id that is not token-shaped must not produce an invalid document")

			// Assert the PROP specifically. A bare Contains on the whole document
			// passes via the risk title, which also carries the id — so it would
			// stay green with the prop deleted, proving nothing.
			require.Equal(t, strings.TrimSpace(id), findingProp(t, out, "hdf-requirement-id"),
				"the source requirement id must be recoverable from the finding")
		})
	}
}

// TestConvertHDFToOSCALSAR_TargetIDMatchesReviewedControls pins the consistency
// the encoding must not break: a finding references a control by id, and that
// control has to appear in the result's reviewed-controls. Encoding one side and
// not the other would produce a document that validates while referencing a
// control it never declares reviewing.
func TestConvertHDFToOSCALSAR_TargetIDMatchesReviewedControls(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"CVE-1/pkg:x/1.0",` +
		`"impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		AR struct {
			Results []struct {
				ReviewedControls struct {
					ControlSelections []struct {
						IncludeControls []struct {
							ControlID string `json:"control-id"`
						} `json:"include-controls"`
					} `json:"control-selections"`
				} `json:"reviewed-controls"`
				Findings []struct {
					Target struct {
						TargetID string `json:"target-id"`
					} `json:"target"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))

	res := doc.AR.Results[0]
	require.Len(t, res.Findings, 1)
	require.Len(t, res.ReviewedControls.ControlSelections, 1)
	require.Len(t, res.ReviewedControls.ControlSelections[0].IncludeControls, 1)
	require.Equal(t,
		res.ReviewedControls.ControlSelections[0].IncludeControls[0].ControlID,
		res.Findings[0].Target.TargetID,
		"a finding must target a control the result declares reviewing")
}

func mustQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// findingProp returns the value of a named prop on the first finding, failing if
// it is absent — the assertion a whole-document Contains cannot make.
func findingProp(t *testing.T, out []byte, name string) string {
	t.Helper()
	var doc struct {
		AR struct {
			Results []struct {
				Findings []struct {
					Props []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"props"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.NotEmpty(t, doc.AR.Results)
	require.NotEmpty(t, doc.AR.Results[0].Findings)
	for _, p := range doc.AR.Results[0].Findings[0].Props {
		if p.Name == name {
			return p.Value
		}
	}
	t.Fatalf("finding carries no %q prop", name)
	return ""
}
