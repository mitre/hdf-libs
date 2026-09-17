package hdftooscalsar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
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
	data, _ := json.Marshal(testhdf.Doc(testhdf.Baseline("test-baseline",
		testhdf.Req("AC-1",
			testhdf.Impact(0.5),
			testhdf.Tag("nist", []interface{}{"AC-1"}),
			testhdf.Desc("Test requirement description"),
			testhdf.Status(status),
			testhdf.CodeDesc("Test code description"),
		))))
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
	assert.Equal(t, "technical", propVal("control-type"))
	assert.Equal(t, "automated", propVal("verification-method"))
	assert.Equal(t, "required", propVal("applicability"))
	assert.Equal(t, "Handbook 3", propVal("reference"))

	// impact > 0: fix text's home is the risk remediation, not a finding prop.
	assert.Empty(t, propVal("fix"))
	require.Len(t, doc.AssessmentResults.Results[0].Risks, 1)
	rems := doc.AssessmentResults.Results[0].Risks[0].Remediations
	require.NotEmpty(t, rems)
	assert.Equal(t, "fix text", rems[0].Description)

	// code is an embedded back-matter resource linked from the finding, not a prop.
	assert.Empty(t, propVal("code"))
	var codeHref string
	var hrefs []string
	for _, l := range finding.Links {
		if l.Rel == "code" {
			codeHref = l.Href
			continue
		}
		hrefs = append(hrefs, l.Href)
	}
	assert.Equal(t, []string{"https://example.gov/a", "https://example.gov/b"}, hrefs)
	require.NotEmpty(t, codeHref)
	require.NotNil(t, doc.AssessmentResults.BackMatter)
	require.Len(t, doc.AssessmentResults.BackMatter.Resources, 1)
	res := doc.AssessmentResults.BackMatter.Resources[0]
	assert.Equal(t, "#"+res.UUID, codeHref)
	require.NotNil(t, res.Base64)
	decoded, err := base64.StdEncoding.DecodeString(res.Base64.Value)
	require.NoError(t, err)
	assert.Contains(t, string(decoded), "control 'SV-1'")

	// url/uri refs are also emitted as observation relevant-evidence so they
	// round-trip through the reverse importer (which ignores finding.links).
	require.Len(t, doc.AssessmentResults.Results[0].Observations, 1)
	ev := doc.AssessmentResults.Results[0].Observations[0].RelevantEvidence
	require.GreaterOrEqual(t, len(ev), 2)
	assert.Equal(t, "https://example.gov/a", ev[0].Href)
	assert.Equal(t, "https://example.gov/b", ev[1].Href)
}

// sarDoc converts HDF input to SAR and decodes it.
func sarDoc(t *testing.T, input []byte) oscal.AssessmentResults {
	t.Helper()
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	return doc.AssessmentResults
}

// propsNamed returns every prop on the list with the given name.
func propsNamed(props []oscal.Property, name string) []oscal.Property {
	var out []oscal.Property
	for _, p := range props {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

// labelledEvidence returns the relevant-evidence entries carrying the HDF
// description-label prop with the given value.
func labelledEvidence(obs *oscal.Observation, label string) []oscal.RelevantEvidence {
	var out []oscal.RelevantEvidence
	for _, e := range obs.RelevantEvidence {
		for _, p := range e.Props {
			if p == oscal.DescriptionLabelProp(label) {
				out = append(out, e)
			}
		}
	}
	return out
}

// hdfDescription returns the data of the first description with the label.
func hdfDescription(req *hdf.EvaluatedRequirement, label string) (string, bool) {
	for _, d := range req.Descriptions {
		if d.Label == label {
			return d.Data, true
		}
	}
	return "", false
}

const multilineRationale = "Without session locks, an unattended session\n  can be used by anyone.\n\nThis matters for shared terminals.\n"
const multilineCheck = "\n  Verify the setting:\n\n  $ sudo grep lock /etc/dconf/db/local.d/*\n\n  If it is missing, this is a finding.\n"
const multilineFix = "Configure the lock:\n\n  $ sudo dconf update\n"

func proseRequirementInput(impact string) []byte {
	return []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-11", "impact": ` + impact + `, "tags": { "nist": ["AC-11"] },
			"descriptions": [
				{ "label": "default", "data": "d" },
				{ "label": "rationale", "data": ` + jsonString(multilineRationale) + ` },
				{ "label": "check", "data": ` + jsonString(multilineCheck) + ` },
				{ "label": "fix", "data": ` + jsonString(multilineFix) + ` }
			],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
		}]}]
	}`)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// rationale's home is finding.target.description, the assessor's conclusion
// about the objective, carried in full rather than as a preview prop.
func TestConvertHDFToOSCALSAR_RationaleInTargetDescription(t *testing.T) {
	sar := sarDoc(t, proseRequirementInput("0.5"))
	f := sar.Results[0].Findings[0]
	assert.Equal(t, multilineRationale, f.Target.Description)
	assert.Empty(t, propsNamed(f.Props, "rationale"), "no rationale prop may remain")
}

func TestConvertHDFToOSCALSAR_NoRationaleLeavesTargetDescriptionEmpty(t *testing.T) {
	sar := sarDoc(t, minimalHDFResults(hdf.Failed))
	assert.Empty(t, sar.Results[0].Findings[0].Target.Description)
}

func TestConvertHDFToOSCALSAR_CheckInRelevantEvidence(t *testing.T) {
	sar := sarDoc(t, proseRequirementInput("0.5"))
	f := sar.Results[0].Findings[0]
	assert.Empty(t, propsNamed(f.Props, "check"), "no check prop may remain")

	require.Len(t, sar.Results[0].Observations, 1)
	obs := &sar.Results[0].Observations[0]
	require.Len(t, f.RelatedObservations, 1)
	assert.Equal(t, obs.UUID, f.RelatedObservations[0].ObservationUUID)

	checks := labelledEvidence(obs, "check")
	require.Len(t, checks, 1)
	assert.Equal(t, "Verify the setting:", checks[0].Description, "description is the single-line preview")
	assert.Equal(t, multilineCheck, checks[0].Remarks, "remarks carries the full text")
	assert.Empty(t, checks[0].Href)
	assert.Equal(t, []oscal.Property{{
		Name: "description-label", Ns: "https://mitre.github.io/hdf-libs/ns/oscal", Value: "check",
	}}, checks[0].Props)
}

func TestConvertHDFToOSCALSAR_CheckPreviewTruncatesLongLine(t *testing.T) {
	long := strings.Repeat("abcdefghij", 20)
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"AC-1","impact":0.5,
		"descriptions":[{"label":"check","data":"` + long + `"}],
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}]}`)
	sar := sarDoc(t, input)
	checks := labelledEvidence(&sar.Results[0].Observations[0], "check")
	require.Len(t, checks, 1)
	assert.Equal(t, long[:117]+"...", checks[0].Description)
	assert.Equal(t, long, checks[0].Remarks)
}

func TestConvertHDFToOSCALSAR_WhitespaceOnlyCheckOmitted(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"AC-1","impact":0.5,
		"descriptions":[{"label":"check","data":"  \n "}],
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}]}`)
	sar := sarDoc(t, input)
	assert.Empty(t, sar.Results[0].Observations[0].RelevantEvidence)
}

func TestConvertHDFToOSCALSAR_ImpactZeroFixInRelevantEvidence(t *testing.T) {
	sar := sarDoc(t, proseRequirementInput("0"))
	f := sar.Results[0].Findings[0]
	assert.Empty(t, propsNamed(f.Props, "fix"), "no fix prop may remain")
	assert.Empty(t, sar.Results[0].Risks, "impact 0 emits no risk")

	fixes := labelledEvidence(&sar.Results[0].Observations[0], "fix")
	require.Len(t, fixes, 1)
	assert.Equal(t, "Configure the lock:", fixes[0].Description)
	assert.Equal(t, multilineFix, fixes[0].Remarks)
	assert.Equal(t, []oscal.Property{{
		Name: "description-label", Ns: "https://mitre.github.io/hdf-libs/ns/oscal", Value: "fix",
	}}, fixes[0].Props)
}

func TestConvertHDFToOSCALSAR_FixRemediationLabelled(t *testing.T) {
	sar := sarDoc(t, proseRequirementInput("0.5"))
	f := sar.Results[0].Findings[0]
	assert.Empty(t, propsNamed(f.Props, "fix"), "no fix prop may remain")
	assert.Empty(t, labelledEvidence(&sar.Results[0].Observations[0], "fix"),
		"impact > 0 carries fix in the risk, not in evidence")

	require.Len(t, sar.Results[0].Risks, 1)
	rems := sar.Results[0].Risks[0].Remediations
	require.Len(t, rems, 1)
	assert.Equal(t, "recommendation", rems[0].Lifecycle)
	assert.Equal(t, multilineFix, rems[0].Description)
	assert.Equal(t, []oscal.Property{{
		Name: "description-label", Ns: "https://mitre.github.io/hdf-libs/ns/oscal", Value: "fix",
	}}, rems[0].Props)
}

func TestConvertHDFToOSCALSAR_AcceptedRemediationUnlabelled(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"AC-1","impact":0.7,
		"descriptions":[{"label":"fix","data":"patch"}],
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}],
		"disposition":"falsePositive",
		"statusOverrides":[{"type":"falsePositive","status":"passed","reason":"r",
			"appliedBy":{"type":"simple","identifier":"jdoe"},
			"appliedAt":"2026-01-02T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z"}]}]}]}`)
	sar := sarDoc(t, input)
	rems := sar.Results[0].Risks[0].Remediations
	require.Len(t, rems, 2)
	assert.Equal(t, "accepted", rems[1].Lifecycle)
	assert.Empty(t, rems[1].Props, "only the fix remediation carries description-label")
}

func TestConvertHDFToOSCALSAR_CodeResourceTypedEvidence(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"AC-1","impact":0.5,
		"code":"control 'AC-1' do end",
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}]}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	require.NotNil(t, doc.AssessmentResults.BackMatter)
	res := doc.AssessmentResults.BackMatter.Resources[0]
	assert.Equal(t, []oscal.Property{{Name: "type", Value: "evidence"}}, res.Props)

	var raw struct {
		AR struct {
			BackMatter struct {
				Resources []map[string]json.RawMessage `json:"resources"`
			} `json:"back-matter"`
		} `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(output, &raw))
	var props []map[string]any
	require.NoError(t, json.Unmarshal(raw.AR.BackMatter.Resources[0]["props"], &props))
	assert.Equal(t, []map[string]any{{"name": "type", "value": "evidence"}}, props,
		"the NIST type prop carries no ns")

	links := doc.AssessmentResults.Results[0].Findings[0].Links
	assert.Equal(t, []oscal.Link{{Href: "#" + res.UUID, Rel: "code"}}, links)
}

// The labelled prose entries follow the entries emitted before them existed, so
// refs, evidence and source location keep their index positions.
func TestConvertHDFToOSCALSAR_LabelledProseAppendedAfterExistingEvidence(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"AC-1","impact":0,
		"descriptions":[{"label":"check","data":"check it"},{"label":"fix","data":"fix it"}],
		"refs":[{"url":"https://example.gov/evidence"}],
		"evidence":[{"type":"log","data":"saw the thing","description":"log excerpt"}],
		"sourceLocation":{"ref":"controls/ac-1.rb","line":42},
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}]}`)
	sar := sarDoc(t, input)
	assert.Equal(t, []oscal.RelevantEvidence{
		{Href: "https://example.gov/evidence"},
		{Description: "log excerpt"},
		{Description: "Source location: controls/ac-1.rb:42"},
		{Description: "check it", Props: []oscal.Property{oscal.DescriptionLabelProp("check")}, Remarks: "check it"},
		{Description: "fix it", Props: []oscal.Property{oscal.DescriptionLabelProp("fix")}, Remarks: "fix it"},
	}, sar.Results[0].Observations[0].RelevantEvidence)
}

// captureWarnings converts input and returns everything the converter logged.
func captureWarnings(t *testing.T, input []byte) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	_, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	return buf.String()
}

// A requirement with no results has no observation, so check and the impact-0
// fix have no home; the loss is reported rather than silent.
func TestConvertHDFToOSCALSAR_WarnsWhenProseHasNoObservation(t *testing.T) {
	const withResults = `,"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]`
	req := func(impact, descriptions, results string) []byte {
		return []byte(`{"baselines":[{"name":"b","requirements":[{"id":"SV-230221","impact":` + impact +
			`,"descriptions":[` + descriptions + `]` + results + `}]}]}`)
	}
	const check = `{"label":"check","data":"check it"}`
	const fix = `{"label":"fix","data":"fix it"}`
	const def = `{"label":"default","data":"d"}`

	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"check only", req("0.5", check+","+fix, ""),
			`WARNING: hdf-to-oscal-sar: requirement "SV-230221" has no results, so no observation holds its check description; it was not carried`},
		{"impact-0 fix only", req("0", fix, ""),
			`WARNING: hdf-to-oscal-sar: requirement "SV-230221" has no results, so no observation holds its fix description; it was not carried`},
		{"check and impact-0 fix", req("0", check+","+fix, ""),
			`WARNING: hdf-to-oscal-sar: requirement "SV-230221" has no results, so no observation holds its check and fix descriptions; they were not carried`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureWarnings(t, tc.input)
			assert.Equal(t, 1, strings.Count(out, "WARNING"), out)
			assert.Contains(t, out, tc.want)
		})
	}

	quoted := captureWarnings(t, []byte(`{"baselines":[{"name":"b","requirements":[{"id":"AC-1 \"x\"","impact":0.5,"descriptions":[`+check+`]}]}]}`))
	assert.Contains(t, quoted, `requirement "AC-1 \"x\"" has no results`, "the id is quoted with escapes")

	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"with results", req("0", check+","+fix, withResults)},
		{"no prose", req("0", def, "")},
		{"impact > 0 fix only", req("0.5", fix, "")},
		{"whitespace-only check", req("0", `{"label":"check","data":"  \n "}`, "")},
	} {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			assert.Empty(t, captureWarnings(t, tc.input))
		})
	}
}

// HDF → SAR → HDF returns rationale, check and fix exactly, on both fix paths,
// without echoing the labelled homes into remediation or evidence descriptions.
func TestConvertHDFToOSCALSAR_ProseRoundTripsExactly(t *testing.T) {
	for _, impact := range []string{"0", "0.5"} {
		t.Run("impact "+impact, func(t *testing.T) {
			output, err := ConvertHDFToOSCALSAR(proseRequirementInput(impact), "1.0.0")
			require.NoError(t, err)
			back, err := oscal.ConvertAssessmentResultsToHDF(output, "1.0.0")
			require.NoError(t, err)
			req := &back.Baselines[0].Requirements[0]

			for label, want := range map[string]string{
				"rationale": multilineRationale, "check": multilineCheck, "fix": multilineFix,
			} {
				got, ok := hdfDescription(req, label)
				require.True(t, ok, "%s description must round-trip", label)
				assert.Equal(t, want, got, "%s must round-trip exactly", label)
			}
			_, hasRemediation := hdfDescription(req, "remediation")
			assert.False(t, hasRemediation, "a labelled fix remediation is not a remediation description")
			_, hasEvidence := hdfDescription(req, "evidence")
			assert.False(t, hasEvidence, "labelled evidence entries are not evidence descriptions")
		})
	}
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
	// A governing waiver drives the finding state; a bare stored value would be
	// ignored (the ladder never reads the effectiveStatus field).
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.5, "tags": { "nist": ["AC-1"] },
			"descriptions": [{ "label": "default", "data": "d" }],
			"results": [{ "status": "passed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }],
			"statusOverrides": [{
				"type": "waiver", "status": "notApplicable", "reason": "scoped out",
				"appliedBy": { "type": "simple", "identifier": "jdoe" },
				"appliedAt": "2026-01-02T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z"
			}]
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

// FedRAMP owns the impact facet, and its rev5 SAR template and extensions
// registry name the system https://fedramp.gov, so that URI is kept deliberately.
func TestConvertHDFToOSCALSAR_ImpactFacetUsesFedRAMPSystem(t *testing.T) {
	input := []byte(`{
		"baselines": [{ "name": "b", "requirements": [{
			"id": "AC-1", "impact": 0.7, "tags": { "nist": ["AC-1"] },
			"descriptions": [{ "label": "default", "data": "d" }],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
		}]}]
	}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	require.Len(t, doc.AssessmentResults.Results[0].Risks, 1)
	assert.Equal(t, []oscal.Facet{{Name: "impact", System: "https://fedramp.gov", Value: "high"}},
		doc.AssessmentResults.Results[0].Risks[0].Characterizations[0].Facets)
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

// a6: the fix description becomes a risk remediation and round-trips as the HDF
// fix description.
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

	hdfResults, err := oscal.ConvertAssessmentResultsToHDF(output, "1.0.0")
	require.NoError(t, err)
	fix, ok := hdfDescription(&hdfResults.Baselines[0].Requirements[0], "fix")
	require.True(t, ok)
	assert.Equal(t, "apply the patch", fix)
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
	data, _ := json.Marshal(testhdf.Doc(testhdf.Baseline("test",
		testhdf.Req("AC-2 (3)",
			testhdf.Impact(0.7),
			testhdf.Tag("nist", []interface{}{"AC-2 (3)"}),
			testhdf.Desc("Enhanced control"),
			testhdf.Status(hdf.Passed),
			testhdf.CodeDesc("test"),
		))))

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
	results := testhdf.Doc(testhdf.Baseline("test",
		testhdf.Req("AC-1",
			testhdf.Impact(0.5),
			testhdf.Tag("nist", []interface{}{"AC-1"}),
			testhdf.Desc("desc"),
			testhdf.Status(hdf.Passed),
			testhdf.CodeDesc("test"),
		)))
	results.PlanRef = &planRef
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

// This test previously asserted that an empty baselines array converted
// successfully to a document with no results. That was the defect: OSCAL
// Assessment Results puts minItems 1 on results, so the emitted document failed
// the schema the converter declares conformance to, while exiting 0.
func TestConvertHDFToOSCALSAR_EmptyBaselines(t *testing.T) {
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{},
	}
	data, _ := json.Marshal(results)

	_, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.Error(t, err, "an assessment with no baselines has no valid OSCAL representation")
	assert.Contains(t, err.Error(), "at least one result")
}

func TestConvertHDFToOSCALSAR_MultipleRequirements(t *testing.T) {
	data, _ := json.Marshal(testhdf.Doc(testhdf.Baseline("multi-test",
		testhdf.Req("AC-1",
			testhdf.Impact(0.5),
			testhdf.Tag("nist", []interface{}{"AC-1"}),
			testhdf.Desc("first"),
			testhdf.Status(hdf.Passed),
			testhdf.CodeDesc("test1"),
		),
		testhdf.Req("AC-2",
			testhdf.Impact(0.7),
			testhdf.Tag("nist", []interface{}{"AC-2"}),
			testhdf.Desc("second"),
			testhdf.Status(hdf.Failed),
			testhdf.CodeDesc("test2"),
		))))

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
	results := testhdf.Doc(testhdf.Baseline("test",
		testhdf.Req("AC-1",
			testhdf.Impact(0.5),
			testhdf.Tag("nist", []interface{}{"AC-1"}),
			testhdf.Desc("desc"),
			testhdf.Status(hdf.Passed),
			testhdf.CodeDesc("test"),
		)))
	results.Baselines[0].Title = &title
	data, _ := json.Marshal(results)

	output, err := ConvertHDFToOSCALSAR(data, "1.0.0")
	require.NoError(t, err)

	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))

	assert.Equal(t, title, doc.AssessmentResults.Results[0].Title)
}

func TestConvertHDFToOSCALSAR_ZeroImpactNoRisk(t *testing.T) {
	data, _ := json.Marshal(testhdf.Doc(testhdf.Baseline("test",
		testhdf.Req("AC-1",
			testhdf.Impact(0.0),
			testhdf.Tag("nist", []interface{}{"AC-1"}),
			testhdf.Desc("desc"),
			testhdf.Status(hdf.Passed),
			testhdf.CodeDesc("test"),
		))))

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

// A stale stored effectiveStatus (no overrides) is never read: the finding
// state reflects the ladder's answer (the failing raw roll-up).
func TestConvertHDFToOSCALSAR_StaleStoredStatusIgnored(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"SV-9","impact":0.7,"title":"t","tags":{},"descriptions":[{"label":"default","data":"d"}],"effectiveStatus":"passed","results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}]}`)
	output, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	status := doc.AssessmentResults.Results[0].Findings[0].Target.Status
	assert.Equal(t, "not-satisfied", status.State)
	assert.Empty(t, status.Reason)
}

// TestConvertHDFToOSCALSAR_NISTRequirementIDControlReferences pins the OSCAL
// references a NIST requirement id produces in any spelling: the control id in
// reviewed-controls, and the finding target, which names a statement for a
// statement-part id. A control selected whole is not narrowed by statement-ids.
func TestConvertHDFToOSCALSAR_NISTRequirementIDControlReferences(t *testing.T) {
	ids := []string{
		"ac-2 (3)", "AC-2 (3)", "Ac-2(3)", "AC-2 (3) (a)",
		"AC-8 c 1", "AC-8 c 2", "AC-08 c 01",
		"Si-2", "SC-7 a", "SC-7",
		"SV-257778",
	}
	reqs := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		reqs = append(reqs, map[string]any{
			"id": id, "impact": 0, "tags": map[string]any{},
			"descriptions": []map[string]any{{"label": "default", "data": "d"}},
			"results":      []map[string]any{{"status": "passed", "codeDesc": "c", "startTime": "2020-01-01T00:00:00Z"}},
		})
	}
	input, err := json.Marshal(map[string]any{"baselines": []map[string]any{{"name": "b", "requirements": reqs}}})
	require.NoError(t, err)

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		AR struct {
			Results []struct {
				ReviewedControls struct {
					ControlSelections []struct {
						IncludeControls []map[string]any `json:"include-controls"`
					} `json:"control-selections"`
				} `json:"reviewed-controls"`
				Findings []struct {
					Target struct {
						Type     string `json:"type"`
						TargetID string `json:"target-id"`
					} `json:"target"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.AR.Results, 1)
	res := doc.AR.Results[0]

	require.Len(t, res.ReviewedControls.ControlSelections, 1)
	assert.Equal(t, []map[string]any{
		{"control-id": "ac-2.3"},
		{"control-id": "ac-8", "statement-ids": []any{"ac-8_smt.c.1", "ac-8_smt.c.2"}},
		{"control-id": "si-2"},
		{"control-id": "sc-7"},
		{"control-id": "sv-257778"},
	}, res.ReviewedControls.ControlSelections[0].IncludeControls)

	type target struct{ typ, id string }
	want := []target{
		{"objective-id", "ac-2.3"}, {"objective-id", "ac-2.3"}, {"objective-id", "ac-2.3"}, {"statement-id", "ac-2.3_smt.a"},
		{"statement-id", "ac-8_smt.c.1"}, {"statement-id", "ac-8_smt.c.2"}, {"statement-id", "ac-8_smt.c.1"},
		{"objective-id", "si-2"}, {"statement-id", "sc-7_smt.a"}, {"objective-id", "sc-7"},
		{"objective-id", "sv-257778"},
	}
	got := make([]target, 0, len(res.Findings))
	for _, f := range res.Findings {
		got = append(got, target{f.Target.Type, f.Target.TargetID})
	}
	assert.Equal(t, want, got)

	for _, file := range arSchemaFiles {
		t.Run(file, func(t *testing.T) {
			requireValidAR(t, arSchemaFor(t, file), "NIST requirement ids", input)
		})
	}
}
