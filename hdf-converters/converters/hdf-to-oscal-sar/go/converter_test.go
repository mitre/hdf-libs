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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The conversion moment lands in these keys; every other date in the output is
// input-derived and must stay asserted.
// Only last-modified is genuinely volatile: it is when the document was written.
// result.start and observation.collected are assessment times derived from the
// input, so the golden asserts them rather than masking them away.
var sarVolatileKeys = []string{"last-modified"}

// TestGoldenParity asserts whole-output equality against a frozen golden.
// The TypeScript test asserts against the SAME file, guaranteeing TS↔Go parity.
// Fresh UUIDs and the conversion timestamp are masked (see shared.MaskVolatileJSON) —
// the UUID reference graph survives masking, so wiring differences still fail.
func TestGoldenParity(t *testing.T) {
	out, err := ConvertHDFToOSCALSAR(fixtures.Results.Minimal, "1.0.0")
	require.NoError(t, err)

	goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-sar", "fixtures", "expected", "minimal.oscal-sar.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
		return
	}

	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "read golden %s", goldenPath)

	maskedGolden, err := shared.MaskVolatileJSON(golden, sarVolatileKeys)
	require.NoError(t, err)
	maskedOut, err := shared.MaskVolatileJSON(out, sarVolatileKeys)
	require.NoError(t, err)

	assert.Equal(t, maskedGolden, maskedOut, "golden mismatch for minimal.oscal-sar.json")
}

// TestConvertRequirementWithoutDescriptionsOrResults documents the Go/TS parity
// contract: descriptions and results are optional on a requirement, and the
// converter must handle their absence without panicking (the TS peer previously
// threw "descriptions is not iterable").
func TestConvertRequirementWithoutDescriptionsOrResults(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "b",
			"requirements": [{ "id": "AC-3", "impact": 0.5, "tags": { "nist": ["AC-3"] } }]
		}]
	}`)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		AssessmentResults oscal.AssessmentResults `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.AssessmentResults.Results, 1)
	require.Len(t, doc.AssessmentResults.Results[0].Findings, 1)
	// No default description → falls back to the requirement id/title.
	assert.Equal(t, "AC-3", doc.AssessmentResults.Results[0].Findings[0].Description)
	// No results → no observation.
	assert.Empty(t, doc.AssessmentResults.Results[0].Observations)
}

// minimalHDFResults returns a minimal valid HDF Results JSON document
// with one baseline, one requirement, and one result.
func minimalHDFResults(status hdf.ResultStatus) []byte {
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name: "test-baseline",
				Requirements: []hdf.EvaluatedRequirement{
					{
						ID:     "AC-1",
						Impact: 0.5,
						Tags: map[string]interface{}{
							"nist": []interface{}{"AC-1"},
						},
						Descriptions: []hdf.Description{
							{Label: "default", Data: "Test requirement description"},
						},
						Results: []hdf.RequirementResult{
							{
								Status:   status,
								CodeDesc: "Test code description",
							},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(results)
	return data
}

func TestConvertHDFToOSCALSAR_EmptyInput(t *testing.T) {
	_, err := ConvertHDFToOSCALSAR(nil, "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertHDFToOSCALSAR_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToOSCALSAR([]byte("{invalid"), "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse HDF JSON")
}

func TestConvertHDFToOSCALSAR_MissingBaselines(t *testing.T) {
	_, err := ConvertHDFToOSCALSAR([]byte(`{}`), "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing baselines")
}

func TestConvertHDFToOSCALSAR_MinimalPassed(t *testing.T) {
	input := minimalHDFResults(hdf.Passed)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	sar := doc.AssessmentResults
	assert.NotEmpty(t, sar.UUID)
	assert.Equal(t, "HDF Assessment Results Export", sar.Metadata.Title)
	assert.Equal(t, oscal.OscalVersion, sar.Metadata.OscalVersion)
	assert.NotNil(t, sar.ImportAP)
	assert.Equal(t, "#", sar.ImportAP.Href)

	require.Len(t, sar.Results, 1)
	result := sar.Results[0]
	assert.NotEmpty(t, result.UUID)
	assert.Equal(t, "test-baseline", result.Title)
	assert.NotEmpty(t, result.Start)

	require.Len(t, result.Findings, 1)
	finding := result.Findings[0]
	assert.NotEmpty(t, finding.UUID)
	assert.Equal(t, "ac-1", finding.Target.TargetID)
	assert.Equal(t, "objective-id", finding.Target.Type)
	assert.Equal(t, "satisfied", finding.Target.Status.State)
	assert.Empty(t, finding.Target.Status.Reason)

	// Should have observation
	assert.Len(t, result.Observations, 1)
	assert.NotEmpty(t, result.Observations[0].UUID)
	assert.Contains(t, result.Observations[0].Description, "passed")

	// Should have risk (impact > 0)
	assert.Len(t, result.Risks, 1)
	assert.Equal(t, "closed", result.Risks[0].Status)
}

func TestConvertHDFToOSCALSAR_FieldCoverage(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "b",
			"requirements": [{
				"id": "SV-1", "impact": 0.7, "title": "req",
				"tags": { "nist": ["AC-2"], "cci": ["CCI-000012"] },
				"descriptions": [
					{ "label": "default", "data": "default desc" },
					{ "label": "check", "data": "check text" },
					{ "label": "fix", "data": "fix text" },
					{ "label": "rationale", "data": "rationale text" }
				],
				"code": "control 'SV-1' do end",
				"controlType": "technical", "verificationMethod": "automated", "applicability": "required",
				"refs": [{ "url": "https://example.gov/a" }, { "uri": "https://example.gov/b" }, { "ref": "Handbook 3" }],
				"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
			}]
		}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	finding := doc.AssessmentResults.Results[0].Findings[0]

	propVal := func(name string) string {
		for _, p := range finding.Props {
			if p.Name == name {
				return p.Value
			}
		}
		return ""
	}
	assert.Equal(t, "CCI-000012", propVal("cci"))
	assert.Contains(t, propVal("code"), "control 'SV-1'")
	assert.Equal(t, "check text", propVal("check"))
	assert.Equal(t, "fix text", propVal("fix"))
	assert.Equal(t, "rationale text", propVal("rationale"))
	assert.Equal(t, "technical", propVal("control-type"))
	assert.Equal(t, "automated", propVal("verification-method"))
	assert.Equal(t, "required", propVal("applicability"))
	assert.Equal(t, "Handbook 3", propVal("reference"))
	var hrefs []string
	for _, l := range finding.Links {
		hrefs = append(hrefs, l.Href)
	}
	assert.Equal(t, []string{"https://example.gov/a", "https://example.gov/b"}, hrefs)

	// url/uri refs are also emitted as observation relevant-evidence so they
	// round-trip through the reverse importer (which ignores finding.links).
	require.Len(t, doc.AssessmentResults.Results[0].Observations, 1)
	var evHrefs []string
	for _, e := range doc.AssessmentResults.Results[0].Observations[0].RelevantEvidence {
		evHrefs = append(evHrefs, e.Href)
	}
	assert.Equal(t, []string{"https://example.gov/a", "https://example.gov/b"}, evHrefs)
}

// a1: the finding target state must reflect effectiveStatus (post-override
// posture), not the raw failing result, and the disposition + override
// provenance must land in target.status.remarks. The governing override expiry
// becomes the risk deadline and an accepted remediation is recorded.
func TestConvertHDFToOSCALSAR_EffectiveStatusAndOverrideProvenance(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "b",
			"requirements": [{
				"id": "AC-1", "impact": 0.7, "tags": { "nist": ["AC-1"] },
				"descriptions": [{ "label": "default", "data": "d" }],
				"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }],
				"effectiveStatus": "passed",
				"disposition": "falsePositive",
				"statusOverrides": [{
					"type": "falsePositive",
					"status": "passed",
					"reason": "scanner mis-detection",
					"appliedBy": { "type": "simple", "identifier": "jdoe" },
					"appliedAt": "2026-01-02T00:00:00Z",
					"expiresAt": "2099-12-31T00:00:00Z"
				}]
			}]
		}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	finding := doc.AssessmentResults.Results[0].Findings[0]
	assert.Equal(t, "satisfied", finding.Target.Status.State,
		"effectiveStatus=passed must win over the raw failed result")
	remarks := finding.Target.Status.Remarks
	assert.Contains(t, remarks, "Disposition: falsePositive")
	assert.Contains(t, remarks, "Override: falsePositive")
	assert.Contains(t, remarks, "Reason: scanner mis-detection")
	assert.Contains(t, remarks, "Applied by: jdoe")
	assert.Contains(t, remarks, "Expires at: 2099-12-31T00:00:00Z")

	// Raw result status is preserved verbatim in the observation.
	assert.Contains(t, doc.AssessmentResults.Results[0].Observations[0].Description, "[failed]")

	risk := doc.AssessmentResults.Results[0].Risks[0]
	assert.Equal(t, "2099-12-31T00:00:00Z", risk.Deadline)
	var accepted *oscal.Remediation
	for i := range risk.Remediations {
		if risk.Remediations[i].Lifecycle == "accepted" {
			accepted = &risk.Remediations[i]
		}
	}
	require.NotNil(t, accepted, "expected an accepted remediation for the governing override")
	assert.Equal(t, "falsePositive", accepted.Title)
	assert.Equal(t, "scanner mis-detection", accepted.Description)
}

// a1: effectiveStatus=notApplicable maps to not-satisfied with reason
// "not-applicable".
func TestConvertHDFToOSCALSAR_EffectiveStatusNotApplicable(t *testing.T) {
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.5, "tags": { "nist": ["AC-1"] },
			"descriptions": [{ "label": "default", "data": "d" }],
			"results": [{ "status": "passed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }],
			"effectiveStatus": "notApplicable"
		}]}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	status := doc.AssessmentResults.Results[0].Findings[0].Target.Status
	assert.Equal(t, "not-satisfied", status.State)
	assert.Equal(t, "not-applicable", status.Reason)
}

// a3: explicit severity drives the risk facet; cwe/epss/kev/cvss surface as
// finding props.
func TestConvertHDFToOSCALSAR_EnrichmentSurfaced(t *testing.T) {
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.3, "tags": { "nist": ["AC-1"] },
			"descriptions": [{ "label": "default", "data": "d" }],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }],
			"severity": "critical",
			"cwe": ["CWE-79", "CWE-89"],
			"epss": { "date": "2026-01-01", "score": 0.97532, "percentile": 0.999 },
			"kev": { "inKev": true, "dateAdded": "2025-01-01", "dueDate": "2025-02-01" },
			"cvss": [{ "version": "3.1", "baseScore": 9.8, "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
		}]}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	finding := doc.AssessmentResults.Results[0].Findings[0]
	propVals := func(name string) []string {
		var vs []string
		for _, p := range finding.Props {
			if p.Name == name {
				vs = append(vs, p.Value)
			}
		}
		return vs
	}
	assert.Equal(t, []string{"CWE-79", "CWE-89"}, propVals("cwe"))
	assert.Equal(t, []string{"0.97532"}, propVals("epss-score"))
	assert.Equal(t, []string{"true"}, propVals("kev"))
	assert.Equal(t, []string{"2025-02-01"}, propVals("kev-due-date"))
	assert.Equal(t, []string{"9.8"}, propVals("cvss-base-score"))

	// Explicit severity (critical) overrides the impact-derived band (low) in the
	// facet the reverse importer reads.
	facet := doc.AssessmentResults.Results[0].Risks[0].Characterizations[0].Facets[0]
	assert.Equal(t, "critical", facet.Value)
}

// a4/a5: evidence, sourceLocation, and refs land in observation
// relevant-evidence and round-trip back to HDF via the reverse importer.
func TestConvertHDFToOSCALSAR_RelevantEvidenceRoundTrips(t *testing.T) {
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.5, "tags": { "nist": ["AC-1"] },
			"descriptions": [{ "label": "default", "data": "d" }],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }],
			"refs": [{ "url": "https://example.gov/evidence" }],
			"evidence": [{ "type": "log", "data": "saw the thing", "description": "log excerpt" }],
			"sourceLocation": { "ref": "controls/ac-1.rb", "line": 42 }
		}]}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	ev := doc.AssessmentResults.Results[0].Observations[0].RelevantEvidence
	var hrefs, descs []string
	for _, e := range ev {
		if e.Href != "" {
			hrefs = append(hrefs, e.Href)
		}
		if e.Description != "" {
			descs = append(descs, e.Description)
		}
	}
	assert.Equal(t, []string{"https://example.gov/evidence"}, hrefs)
	assert.Contains(t, descs, "log excerpt")
	assert.Contains(t, descs, "Source location: controls/ac-1.rb:42")

	// Round-trip: the reverse importer reads the ref href back into HDF refs.
	hdfResults, err := oscal.ConvertAssessmentResultsToHDF(output, "1.0.0")
	require.NoError(t, err)
	req := hdfResults.Baselines[0].Requirements[0]
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://example.gov/evidence", *req.Refs[0].URL)
}

// a6: the fix description becomes a risk remediation (round-trips as the HDF
// remediation description), not merely a prop.
func TestConvertHDFToOSCALSAR_FixBecomesRemediation(t *testing.T) {
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.5, "tags": { "nist": ["AC-1"] },
			"descriptions": [
				{ "label": "default", "data": "d" },
				{ "label": "fix", "data": "apply the patch" }
			],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
		}]}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	rems := doc.AssessmentResults.Results[0].Risks[0].Remediations
	require.NotEmpty(t, rems)
	assert.Equal(t, "recommendation", rems[0].Lifecycle)
	assert.Equal(t, "apply the patch", rems[0].Description)

	// Round-trips into the HDF remediation description.
	hdfResults, err := oscal.ConvertAssessmentResultsToHDF(output, "1.0.0")
	require.NoError(t, err)
	var remediationDesc string
	for _, d := range hdfResults.Baselines[0].Requirements[0].Descriptions {
		if d.Label == "remediation" {
			remediationDesc = d.Data
		}
	}
	assert.Contains(t, remediationDesc, "apply the patch")
}

// a7: externalReferences with an href become finding links.
func TestConvertHDFToOSCALSAR_ExternalReferencesBecomeLinks(t *testing.T) {
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.5, "tags": { "nist": ["AC-1"] },
			"descriptions": [{ "label": "default", "data": "d" }],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }],
			"externalReferences": [{ "sourceName": "cve", "href": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }]
		}]}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	var hrefs []string
	for _, l := range doc.AssessmentResults.Results[0].Findings[0].Links {
		hrefs = append(hrefs, l.Href)
	}
	assert.Contains(t, hrefs, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
}

// a2/a8: the shared minimal fixture carries a component and a baseline version;
// both must surface (subjects on the observation, baseline-version result prop).
func TestConvertHDFToOSCALSAR_ComponentsAndBaselineVersion(t *testing.T) {
	output, err := ConvertHDFToOSCALSAR(fixtures.Results.Minimal, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	result := doc.AssessmentResults.Results[0]

	var baselineVersion string
	for _, p := range result.Props {
		if p.Name == "baseline-version" {
			baselineVersion = p.Value
		}
	}
	assert.Equal(t, "1.0.0", baselineVersion)

	require.Len(t, result.Observations, 1)
	require.Len(t, result.Observations[0].Subjects, 1)
	subj := result.Observations[0].Subjects[0]
	assert.Equal(t, "web-server-01", subj.Title)
	assert.Equal(t, "host", subj.Type)
	assert.NotEmpty(t, subj.SubjectUUID)
}

func TestConvertHDFToOSCALSAR_MinimalFailed(t *testing.T) {
	input := minimalHDFResults(hdf.Failed)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	finding := doc.AssessmentResults.Results[0].Findings[0]
	assert.Equal(t, "not-satisfied", finding.Target.Status.State)

	// Risk should be open for failed
	risk := doc.AssessmentResults.Results[0].Risks[0]
	assert.Equal(t, "open", risk.Status)
}

func TestConvertHDFToOSCALSAR_StatusMapping(t *testing.T) {
	tests := []struct {
		name          string
		hdfStatus     hdf.ResultStatus
		expectedState string
		expectedOpen  string
	}{
		{"passed -> satisfied", hdf.Passed, "satisfied", "closed"},
		{"failed -> not-satisfied", hdf.Failed, "not-satisfied", "open"},
		{"error -> not-satisfied", hdf.Error, "not-satisfied", "open"},
		{"notReviewed -> not-satisfied", hdf.NotReviewed, "not-satisfied", "open"},
		{"notApplicable -> not-satisfied", hdf.NotApplicable, "not-satisfied", "open"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := minimalHDFResults(tc.hdfStatus)
			output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
			require.NoError(t, err)

			var doc oscalSARDocument
			require.NoError(t, json.Unmarshal(output, &doc))

			finding := doc.AssessmentResults.Results[0].Findings[0]
			assert.Equal(t, tc.expectedState, finding.Target.Status.State)

			risk := doc.AssessmentResults.Results[0].Risks[0]
			assert.Equal(t, tc.expectedOpen, risk.Status)
		})
	}
}

func TestConvertHDFToOSCALSAR_EnhancedControlID(t *testing.T) {
	// Build HDF with an enhanced control like "AC-2 (3)"
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name: "test",
				Requirements: []hdf.EvaluatedRequirement{
					{
						ID:     "AC-2 (3)",
						Impact: 0.7,
						Tags:   map[string]interface{}{"nist": []interface{}{"AC-2 (3)"}},
						Descriptions: []hdf.Description{
							{Label: "default", Data: "Enhanced control"},
						},
						Results: []hdf.RequirementResult{
							{Status: hdf.Passed, CodeDesc: "test"},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	finding := doc.AssessmentResults.Results[0].Findings[0]
	assert.Equal(t, "ac-2.3", finding.Target.TargetID)
}

func TestConvertHDFToOSCALSAR_UUIDsUnique(t *testing.T) {
	input := minimalHDFResults(hdf.Failed)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	uuids := make(map[string]bool)
	uuids[doc.AssessmentResults.UUID] = true

	for _, result := range doc.AssessmentResults.Results {
		assert.False(t, uuids[result.UUID], "duplicate UUID: %s", result.UUID)
		uuids[result.UUID] = true

		for _, f := range result.Findings {
			assert.False(t, uuids[f.UUID], "duplicate UUID: %s", f.UUID)
			uuids[f.UUID] = true
		}
		for _, o := range result.Observations {
			assert.False(t, uuids[o.UUID], "duplicate UUID: %s", o.UUID)
			uuids[o.UUID] = true
		}
		for _, r := range result.Risks {
			assert.False(t, uuids[r.UUID], "duplicate UUID: %s", r.UUID)
			uuids[r.UUID] = true
		}
	}
}

func TestConvertHDFToOSCALSAR_PlanRef(t *testing.T) {
	planRef := "https://example.com/assessment-plan"
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name: "test",
				Requirements: []hdf.EvaluatedRequirement{
					{
						ID: "AC-1", Impact: 0.5,
						Tags:         map[string]interface{}{"nist": []interface{}{"AC-1"}},
						Descriptions: []hdf.Description{{Label: "default", Data: "desc"}},
						Results:      []hdf.RequirementResult{{Status: hdf.Passed, CodeDesc: "test"}},
					},
				},
			},
		},
		PlanRef: &planRef,
	}
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	assert.Equal(t, planRef, doc.AssessmentResults.ImportAP.Href)
}

func TestConvertHDFToOSCALSAR_ImpactSeverityMapping(t *testing.T) {
	tests := []struct {
		impact   float64
		severity string
	}{
		{0.9, "critical"},
		{0.7, "high"},
		{0.5, "moderate"},
		{0.3, "low"},
		{0.0, "info"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.severity, oscal.ImpactToSeverity(tc.impact))
	}
}

func TestConvertHDFToOSCALSAR_NistTagToControlID(t *testing.T) {
	tests := []struct {
		tag      string
		expected string
	}{
		{"AC-1", "ac-1"},
		{"AC-2 (3)", "ac-2.3"},
		{"SI-7 (1)", "si-7.1"},
		{"CM-6", "cm-6"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.expected, oscal.NistTagToControlID(tc.tag))
	}
}

func TestConvertHDFToOSCALSAR_EmptyBaselines(t *testing.T) {
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{},
	}
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	assert.Empty(t, doc.AssessmentResults.Results)
}

func TestConvertHDFToOSCALSAR_MultipleRequirements(t *testing.T) {
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name: "multi-test",
				Requirements: []hdf.EvaluatedRequirement{
					{
						ID: "AC-1", Impact: 0.5,
						Tags:         map[string]interface{}{"nist": []interface{}{"AC-1"}},
						Descriptions: []hdf.Description{{Label: "default", Data: "first"}},
						Results:      []hdf.RequirementResult{{Status: hdf.Passed, CodeDesc: "test1"}},
					},
					{
						ID: "AC-2", Impact: 0.7,
						Tags:         map[string]interface{}{"nist": []interface{}{"AC-2"}},
						Descriptions: []hdf.Description{{Label: "default", Data: "second"}},
						Results:      []hdf.RequirementResult{{Status: hdf.Failed, CodeDesc: "test2"}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	require.Len(t, doc.AssessmentResults.Results, 1)
	assert.Len(t, doc.AssessmentResults.Results[0].Findings, 2)
	assert.Len(t, doc.AssessmentResults.Results[0].Observations, 2)
	assert.Len(t, doc.AssessmentResults.Results[0].Risks, 2)
}

// TestConvertHDFToOSCALSAR_RoundTrip verifies that converting SAR -> HDF -> SAR
// preserves the structure (same number of findings). This is not exact equality
// since UUIDs change and some data is lossy.
func TestConvertHDFToOSCALSAR_RoundTrip(t *testing.T) {
	sarFixture := filepath.Join("..", "..", "oscal-to-hdf", "fixtures", "input", "sar-fedramp.json")
	sarData, err := os.ReadFile(sarFixture)
	if err != nil {
		t.Skip("SAR fixture not available at", sarFixture)
	}

	// Step 1: SAR -> HDF
	hdfResults, err := oscal.ConvertAssessmentResultsToHDF(sarData, "1.0.0")
	require.NoError(t, err)
	require.NotNil(t, hdfResults)

	hdfJSON, err := json.Marshal(hdfResults)
	require.NoError(t, err)

	// Step 2: HDF -> SAR
	sarOutput, err := ConvertHDFToOSCALSAR(hdfJSON, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(sarOutput, &doc))

	// Verify structure is preserved: same number of results and findings count matches
	// requirements count from the intermediate HDF
	require.Len(t, doc.AssessmentResults.Results, len(hdfResults.Baselines))
	for i, result := range doc.AssessmentResults.Results {
		assert.Len(t, result.Findings, len(hdfResults.Baselines[i].Requirements),
			"findings count should match requirements count for baseline %d", i)
	}

	// Verify valid OSCAL structure
	assert.NotEmpty(t, doc.AssessmentResults.UUID)
	assert.Equal(t, oscal.OscalVersion, doc.AssessmentResults.Metadata.OscalVersion)
	assert.NotNil(t, doc.AssessmentResults.ImportAP)
}

func TestConvertHDFToOSCALSAR_ValidJSON(t *testing.T) {
	input := minimalHDFResults(hdf.Passed)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	// Verify output is valid JSON with the assessment-results root key
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(output, &raw))
	assert.Contains(t, raw, "assessment-results")
}

func TestConvertHDFToOSCALSAR_BaselineTitle(t *testing.T) {
	title := "My Custom Baseline Title"
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name:  "test",
				Title: &title,
				Requirements: []hdf.EvaluatedRequirement{
					{
						ID: "AC-1", Impact: 0.5,
						Tags:         map[string]interface{}{"nist": []interface{}{"AC-1"}},
						Descriptions: []hdf.Description{{Label: "default", Data: "desc"}},
						Results:      []hdf.RequirementResult{{Status: hdf.Passed, CodeDesc: "test"}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	assert.Equal(t, title, doc.AssessmentResults.Results[0].Title)
}

func TestConvertHDFToOSCALSAR_ZeroImpactNoRisk(t *testing.T) {
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name: "test",
				Requirements: []hdf.EvaluatedRequirement{
					{
						ID: "AC-1", Impact: 0.0,
						Tags:         map[string]interface{}{"nist": []interface{}{"AC-1"}},
						Descriptions: []hdf.Description{{Label: "default", Data: "desc"}},
						Results:      []hdf.RequirementResult{{Status: hdf.Passed, CodeDesc: "test"}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	// Zero impact should not produce a risk
	assert.Empty(t, doc.AssessmentResults.Results[0].Risks)
	// Finding should have no related risks
	assert.Empty(t, doc.AssessmentResults.Results[0].Findings[0].RelatedRisks)
}

// OSCAL result.start means when the ASSESSMENT ran. HDF carries that on each
// requirement result (startTime); the document-level timestamp is when the HDF
// file was produced. Stamping the document timestamp (or time.Now) into
// result.start reports the conversion time and drops the real assessment time.
func TestConvertHDFToOSCALSAR_StartIsAssessmentTimeNotConversionTime(t *testing.T) {
	// Document produced long after the scan ran.
	const documentTimestamp = "2026-07-13T09:00:00Z"
	const earliestScan = "2026-03-01T08:15:00Z"
	const laterScan = "2026-03-01T09:45:00Z"

	input := []byte(`{
		"timestamp": "` + documentTimestamp + `",
		"baselines": [{
			"name": "b1",
			"requirements": [{
				"id": "AC-1", "impact": 0.5,
				"descriptions": [{"label": "default", "data": "d"}],
				"tags": {"nist": ["AC-1"]},
				"results": [
					{"status": "passed", "codeDesc": "c", "startTime": "` + laterScan + `"},
					{"status": "failed", "codeDesc": "c", "startTime": "` + earliestScan + `"}
				]
			}]
		}]
	}`)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.AssessmentResults.Results, 1)

	start := doc.AssessmentResults.Results[0].Start
	assert.Equal(t, earliestScan, start,
		"result.start must be the earliest assessment time, not the conversion time")
	assert.NotEqual(t, documentTimestamp, start,
		"result.start must not be the document timestamp")

	// observation.collected means when the evidence was gathered, so it is the
	// scan time for that requirement — not the conversion time either.
	require.Len(t, doc.AssessmentResults.Results[0].Observations, 1)
	collected := doc.AssessmentResults.Results[0].Observations[0].Collected
	assert.Equal(t, earliestScan, collected,
		"observation.collected must be the assessment time, not the conversion time")
}
