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
