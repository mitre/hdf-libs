package splunk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func loadEventsFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "splunk-to-hdf", "fixtures", "input", "splunk-events.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read splunk-events.json fixture")
	return data
}

func loadMinimalFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "splunk-to-hdf", "fixtures", "input", "splunk-minimal.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read splunk-minimal.json fixture")
	return data
}

// ---- Structure tests ----

func TestConvertSplunkToHDF_Events(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	assert.NotEmpty(t, result.Baselines, "Baselines should not be empty")

	// The fixture has 1 profile, so we should have 1 baseline
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "disa_stig-el7", baseline.Name)
	assert.Len(t, baseline.Requirements, 6, "Expected 6 controls from events fixture")
}

func TestConvertSplunkToHDF_Minimal(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "disa_stig-el7", baseline.Name)
	require.Len(t, baseline.Requirements, 1, "Minimal fixture has 1 control")
	require.Len(t, baseline.Requirements[0].Results, 1, "Minimal control has 1 result")
}

// ---- Error tests ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "splunk-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertSplunkToHDF(input, testConverterVersion) },
		MinimalFixture: "splunk-events.json",
	})
}

func TestConvertSplunkToHDF_EmptyArray(t *testing.T) {
	_, err := ConvertSplunkToHDF([]byte("[]"), testConverterVersion)
	assert.Error(t, err, "Should fail on empty array")
	assert.Contains(t, err.Error(), "no Splunk events found in input")
}

func TestConvertSplunkToHDF_NoHeader(t *testing.T) {
	// Craft input with only a control event (no header)
	input := []byte(`[{
		"meta": {"guid": "test-guid", "subtype": "control", "hdf_splunk_schema": "1.0", "filetype": "evaluation", "filename": "test.json", "profile_sha256": "abc123"},
		"id": "V-12345", "title": "Test", "desc": "", "descriptions": {}, "impact": 0.5, "code": "", "tags": {}, "results": [], "refs": []
	}]`)
	_, err := ConvertSplunkToHDF(input, testConverterVersion)
	assert.Error(t, err, "Should fail with no header")
	assert.Contains(t, err.Error(), "expected 1 header event, got 0")
}

// ---- Descriptions test ----

func TestConvertSplunkToHDF_Descriptions(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		require.NotEmpty(t, req.Descriptions, "Requirement %s should have descriptions", req.ID)
		for _, desc := range req.Descriptions {
			assert.NotEmpty(t, desc.Label, "Description label should not be empty for requirement %s", req.ID)
		}
	}

	// Verify specific descriptions are converted from object to array format
	// The fixture controls have "default", "check", and "fix" description keys
	found := false
	for _, req := range baseline.Requirements {
		labels := make(map[string]bool)
		for _, desc := range req.Descriptions {
			labels[desc.Label] = true
		}
		if labels["default"] && labels["check"] && labels["fix"] {
			found = true
			break
		}
	}
	assert.True(t, found, "At least one requirement should have default, check, and fix descriptions")
}

// ---- Tags test ----

func TestConvertSplunkToHDF_Tags(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		require.NotNil(t, req.Tags, "Requirement %s should have tags", req.ID)
	}

	// Find the first control and verify it has NIST tags
	req := baseline.Requirements[0]
	nistTag, hasNist := req.Tags["nist"]
	assert.True(t, hasNist, "Control should have nist tags")
	assert.NotNil(t, nistTag, "NIST tag should not be nil")
}

// ---- Result status test ----

func TestConvertSplunkToHDF_ResultStatus(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	statusCounts := map[hdf.ResultStatus]int{}
	for _, req := range baseline.Requirements {
		for _, res := range req.Results {
			statusCounts[res.Status]++
		}
	}

	// The fixture has 3 passed controls and 3 failed controls
	assert.Greater(t, statusCounts[hdf.Passed], 0, "Should have at least one passed result")
	assert.Greater(t, statusCounts[hdf.Failed], 0, "Should have at least one failed result")
}

// ---- Target test ----

func TestConvertSplunkToHDF_Target(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components, "Should have at least one target")
	target := result.Components[0]
	assert.Equal(t, "centos", target.Name, "Target name should come from platform.name")
	assert.Equal(t, hdf.Host, target.Type, "Target type should be Host")
}

// ---- Impact test ----

func TestConvertSplunkToHDF_Impact(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		// All controls in the fixture have impact 0.5
		assert.Equal(t, 0.5, req.Impact, "Impact should be preserved from control.impact for %s", req.ID)
	}
}

// ---- Source location test ----

func TestConvertSplunkToHDF_SourceLocation(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	found := false
	for _, req := range baseline.Requirements {
		if req.SourceLocation != nil {
			found = true
			assert.NotNil(t, req.SourceLocation.Ref, "SourceLocation.Ref should be set")
			assert.NotNil(t, req.SourceLocation.Line, "SourceLocation.Line should be set")
			break
		}
	}
	assert.True(t, found, "At least one requirement should have a source location")
}

// ---- Generator test ----

func TestConvertSplunkToHDF_Generator(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator, "Generator should not be nil")
	assert.Equal(t, "splunk-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

// ---- Checksum test ----

func TestConvertSplunkToHDF_Checksum(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	require.NotNil(t, baseline.ResultsChecksum, "ResultsChecksum should be present")
	assert.Equal(t, hdf.Sha256, baseline.ResultsChecksum.Algorithm, "Checksum algorithm should be sha256")
	assert.Len(t, baseline.ResultsChecksum.Value, 64, "Checksum value should be 64 hex chars")
}

// ---- Statistics test ----

func TestConvertSplunkToHDF_Statistics(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Statistics, "Statistics should not be nil")
	require.NotNil(t, result.Statistics.Duration, "Duration should not be nil")
	assert.InDelta(t, 10.681, *result.Statistics.Duration, 0.01, "Duration should match header.statistics.duration")
}

// ---- Profile fields test ----

func TestConvertSplunkToHDF_ProfileFields(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	assert.NotNil(t, baseline.Title, "Title should be set")
	assert.Equal(t, "DISA RedHat Enterprise Linux 7 STIG - v1r4", *baseline.Title)
	assert.NotNil(t, baseline.Version, "Version should be set")
	assert.Equal(t, "0.2.0", *baseline.Version)
	assert.NotEmpty(t, baseline.Groups, "Groups should not be empty")
}

// ---- Multiple results per control ----

func TestConvertSplunkToHDF_MultipleResults(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	foundMultiple := false
	for _, req := range baseline.Requirements {
		if len(req.Results) > 1 {
			foundMultiple = true
			break
		}
	}
	assert.True(t, foundMultiple, "At least one control should have multiple results")
}

// ---- JSON round-trip test ----

func TestConvertSplunkToHDF_JSONRoundTrip(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)

	// Marshal to JSON
	output, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err, "Should marshal to JSON")

	// Verify it's valid JSON by unmarshaling back
	var parsed map[string]interface{}
	err = json.Unmarshal(output, &parsed)
	require.NoError(t, err, "Output should be valid JSON")

	// Verify expected top-level keys
	assert.Contains(t, parsed, "baselines")
	assert.Contains(t, parsed, "components")
	assert.Contains(t, parsed, "generator")
}

func TestConvertSplunkToHDF_ControlType(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

// countSplunkControlEvents walks the raw Splunk event array — deliberately NOT
// the converter's structs — and returns the number of events whose
// meta.subtype is "control". Splunk input is a flat array of header/profile/
// control events; the converter emits exactly one requirement per control
// event, so the control-event count is the emission-unit ground truth
// (header and profile events must be excluded).
func countSplunkControlEvents(t *testing.T, input []byte) int {
	t.Helper()
	var events []struct {
		Meta struct {
			Subtype string `json:"subtype"`
		} `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(input, &events), "failed to parse Splunk JSON for anchor count")
	n := 0
	for _, e := range events {
		if e.Meta.Subtype == "control" {
			n++
		}
	}
	return n
}

// Ground-truth anchor: the converter emits one requirement per control event
// (meta.subtype == "control"). The count is derived independently of the
// converter's parser, so a silent under-extraction (e.g. dropping a control
// event) fails even when Go/TS golden parity agrees. splunk-events.json holds
// 8 events, of which 6 are controls.
func TestConvertSplunkToHDF_ControlEventAnchor(t *testing.T) {
	input := loadEventsFixture(t)
	result, err := ConvertSplunkToHDF(input, testConverterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countSplunkControlEvents(t, input),
		"splunk-events.json: one requirement per meta.subtype==control event")
}

// ---- Tool version test ----

// header.version carries the Splunk scanner/format version; it maps to HDF
// tool.version. The value is a static string in the source, so the assertion
// pins the exact fixture version (the snapshot masks timestamps, not this).
func TestConvertSplunkToHDF_ToolVersion(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Tool, "Tool should be set")
	require.NotNil(t, result.Tool.Version, "tool.version should be set from header.version")
	assert.Equal(t, "4.16.0", *result.Tool.Version)

	minResult, err := ConvertSplunkToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, minResult.Tool)
	require.NotNil(t, minResult.Tool.Version)
	assert.Equal(t, "4.16.0", *minResult.Tool.Version)
}

// When the header carries no version, tool.version stays absent rather than
// serializing an empty string.
func TestConvertSplunkToHDF_ToolVersionAbsent(t *testing.T) {
	input := []byte(`[{
		"meta": {"guid": "g", "subtype": "header", "hdf_splunk_schema": "1.0", "filetype": "evaluation", "filename": "t.json"},
		"profiles": [], "platform": {"name": "centos", "release": "7"}, "statistics": {}
	}]`)
	result, err := ConvertSplunkToHDF(input, testConverterVersion)
	require.NoError(t, err)
	if result.Tool != nil {
		assert.Nil(t, result.Tool.Version, "tool.version should be absent when header.version is empty")
	}
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "splunk-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSplunkToHDF(input, "1.0.0")
	})
}

func TestConvertSplunkToHDF_VerificationMethod(t *testing.T) {
	result, err := ConvertSplunkToHDF(loadEventsFixture(t), testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}

func TestMapStatus_CaseInsensitive(t *testing.T) {
	// Splunk-stored statuses are canonically lowercase, but a case-variant
	// document must map by meaning rather than collapse to notReviewed; the
	// TS peer already folds case.
	assert.Equal(t, hdf.Passed, mapStatus("Passed"))
	assert.Equal(t, hdf.Failed, mapStatus("FAILED"))
	assert.Equal(t, hdf.NotReviewed, mapStatus("Skipped"))
	assert.Equal(t, hdf.Error, mapStatus("Error"))
	assert.Equal(t, hdf.NotReviewed, mapStatus("wibble"))
}

// A stored control with no impact field is UNKNOWN severity, not zero severity,
// so it resolves to the unknown-severity default. This replaces a test that
// pinned 0.0 as "the float zero value" — Go's non-pointer field made absent and
// explicit-0 the same value, so that test recorded an artifact rather than a
// decision. Its one real insight is kept: the TS peer must agree, and it used to
// drop the schema-required field entirely.
func TestAbsentImpact_IsUnknownSeverity(t *testing.T) {
	var events []map[string]interface{}
	require.NoError(t, json.Unmarshal(loadMinimalFixture(t), &events))
	for _, e := range events {
		if meta, ok := e["meta"].(map[string]interface{}); ok && meta["subtype"] == "control" {
			delete(e, "impact")
		}
	}
	raw, err := json.Marshal(events)
	require.NoError(t, err)
	result, err := ConvertSplunkToHDF(raw, testConverterVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Baselines[0].Requirements)
	for _, req := range result.Baselines[0].Requirements {
		assert.InDelta(t, 0.5, req.Impact, 0.0001,
			"absent impact means we do not know the severity, not that there is none")
		statuses := make([]hdf.ResultStatus, 0, len(req.Results))
		for _, r := range req.Results {
			statuses = append(statuses, r.Status)
		}
		assert.NotContains(t, statuses, hdf.NotApplicable,
			"nothing declared this control inapplicable, so no notApplicable is synthesized")
	}

	// The schema-required field must still be present and valid.
	out, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.Validate(out, validators.TypeResults)
	assert.Truef(t, v.Valid, "absent-impact output must validate: %s", v.Error())
}

// TestConvertSplunk_ImpactZeroSkipsTranslate is the divergence this fixes: the
// same InSpec run read from Splunk must produce the same statuses as the same run
// read from a file. legacyhdf-to-hdf translates InSpec's score-0-and-skip
// convention into an explicit notApplicable result; this reader of the same
// control payload did not, so one scan reported notApplicable through one path
// and notReviewed through the other — and notReviewed is in the compliance
// denominator while notApplicable is not.
func TestConvertSplunk_ImpactZeroSkipsTranslate(t *testing.T) {
	path := filepath.Join(shared.GetConvertersDir(), "splunk-to-hdf", "fixtures", "input", "splunk-impact-zero-skips.json")
	input, err := os.ReadFile(path)
	require.NoError(t, err)

	out, err := ConvertSplunkToHDF(input, testConverterVersion)
	require.NoError(t, err)

	byID := map[string]*hdf.EvaluatedRequirement{}
	for i := range out.Baselines[0].Requirements {
		r := &out.Baselines[0].Requirements[i]
		byID[r.ID] = r
	}

	// The three impact-0 skip-only controls from the real export.
	for _, id := range []string{"V-72317", "V-72313", "V-72305"} {
		t.Run(id, func(t *testing.T) {
			req := byID[id]
			require.NotNil(t, req, "requirement %s missing", id)
			assert.Zero(t, req.Impact, "precondition: the source scored this 0")

			statuses := make([]hdf.ResultStatus, 0, len(req.Results))
			for _, r := range req.Results {
				statuses = append(statuses, r.Status)
			}
			assert.Contains(t, statuses, hdf.NotApplicable,
				"the scope declaration must be stated as a result, as the file importer does")
		})
	}

	// The controls that did establish a verdict are untouched.
	require.NotNil(t, byID["V-77825"])
	assert.Equal(t, hdf.Passed, byID["V-77825"].Results[0].Status)
	require.NotNil(t, byID["V-78997"])
	assert.Equal(t, hdf.Failed, byID["V-78997"].Results[0].Status)
}

// loadImpactZeroFixture returns the real trimmed Splunk export carrying the
// impact-0 skip-only shape.
func loadImpactZeroFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "splunk-to-hdf", "fixtures", "input", "splunk-impact-zero-skips.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// TestConvertSplunk_ImpactZeroNoResultsTranslates covers the case the predicate
// admits but a caller can forget: InSpecEstablishedNothing is true for an EMPTY
// result set, so the synthesized result must not assume a result already exists.
// legacyhdf-to-hdf has the same test; splunk did not, and the TS twin crashed
// here before the shared builder was hoisted. Derived from the real fixture by
// emptying one control's results, so only that one field differs from real data.
func TestConvertSplunk_ImpactZeroNoResultsTranslates(t *testing.T) {
	var events []map[string]interface{}
	require.NoError(t, json.Unmarshal(loadImpactZeroFixture(t), &events))
	for _, e := range events {
		if e["id"] == "V-72317" {
			e["results"] = []interface{}{}
		}
	}
	doc, err := json.Marshal(events)
	require.NoError(t, err)

	out, err := ConvertSplunkToHDF(doc, testConverterVersion)
	require.NoError(t, err)

	var req *hdf.EvaluatedRequirement
	for i := range out.Baselines[0].Requirements {
		if out.Baselines[0].Requirements[i].ID == "V-72317" {
			req = &out.Baselines[0].Requirements[i]
		}
	}
	require.NotNil(t, req, "V-72317 must still be emitted")
	require.Len(t, req.Results, 1, "the synthesized result is the only one")
	assert.Equal(t, hdf.NotApplicable, req.Results[0].Status)
	assert.NotEmpty(t, req.Results[0].CodeDesc, "the synthesized result must be fully populated")
	// With no result to take a time from, the fallback is Go's zero time, which
	// is what the TS twin asserts too — the two must not drift.
	assert.True(t, req.Results[0].StartTime.IsZero(),
		"an empty result set leaves no time to inherit, so the zero time is the convention")
}

// TestConvertSplunk_AgreesWithLegacyhdfOnTheSameControl is the contract this card
// exists for: one InSpec run must produce one document whichever reader sees it.
// The legacy document is built from the SAME control payload the Splunk export
// carries, so a future divergence in either reader fails here rather than
// surfacing as drift in a consumer's diff.
func TestConvertSplunk_AgreesWithLegacyhdfOnTheSameControl(t *testing.T) {
	var events []map[string]interface{}
	require.NoError(t, json.Unmarshal(loadImpactZeroFixture(t), &events))

	var control map[string]interface{}
	for _, e := range events {
		if e["id"] == "V-72317" {
			control = e
		}
	}
	require.NotNil(t, control, "fixture must carry V-72317")

	// The same control, expressed as InSpec exec JSON rather than a Splunk event.
	v1Control := map[string]interface{}{
		"id":      control["id"],
		"title":   control["title"],
		"impact":  control["impact"],
		"results": control["results"],
	}
	legacyDoc, err := json.Marshal(map[string]interface{}{
		"platform":   map[string]interface{}{"name": "centos", "release": "7"},
		"version":    "4.16.0",
		"statistics": map[string]interface{}{},
		"profiles": []interface{}{map[string]interface{}{
			"name":     "p",
			"sha256":   "abc",
			"controls": []interface{}{v1Control},
		}},
	})
	require.NoError(t, err)

	fromSplunk, err := ConvertSplunkToHDF(loadImpactZeroFixture(t), testConverterVersion)
	require.NoError(t, err)
	v1, err := legacyhdf.ParseLegacyHDF(legacyDoc)
	require.NoError(t, err)
	fromFile := legacyhdf.ConvertLegacyHDF(v1, testConverterVersion)

	synthesized := func(out *hdf.HDFResults, id string) hdf.RequirementResult {
		t.Helper()
		for _, b := range out.Baselines {
			for _, r := range b.Requirements {
				if r.ID != id {
					continue
				}
				for _, res := range r.Results {
					if res.Status == hdf.NotApplicable {
						return res
					}
				}
			}
		}
		t.Fatalf("no synthesized notApplicable result for %s", id)
		return hdf.RequirementResult{}
	}

	a := synthesized(fromSplunk, "V-72317")
	b := synthesized(fromFile, "V-72317")
	assert.Equal(t, b.Status, a.Status, "status must match the file importer")
	assert.Equal(t, b.CodeDesc, a.CodeDesc, "codeDesc must match byte for byte")
	assert.Equal(t, b.StartTime, a.StartTime, "the startTime convention must match")
}

// A control event with no tags must still carry a tags object — tags is in
// Evaluated_Requirement.required, so null is invalid. The file importer had the
// same defect; these are the same InSpec controls, so both readers are fixed.
func TestConvertSplunk_TaglessControlIsSchemaValid(t *testing.T) {
	var events []map[string]interface{}
	require.NoError(t, json.Unmarshal(loadMinimalFixture(t), &events))
	for _, e := range events {
		if meta, ok := e["meta"].(map[string]interface{}); ok && meta["subtype"] == "control" {
			delete(e, "tags")
		}
	}
	raw, err := json.Marshal(events)
	require.NoError(t, err)

	out, err := ConvertSplunkToHDF(raw, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, out.Baselines[0].Requirements)
	for _, req := range out.Baselines[0].Requirements {
		require.NotNil(t, req.Tags, "tags is schema-required, so it cannot be nil")
		assert.Empty(t, req.Tags)
	}

	serialized, err := json.Marshal(out)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), `"tags":null`)
	v := validators.Validate(serialized, validators.TypeResults)
	assert.Truef(t, v.Valid, "tagless output must validate: %s", v.Error())
}

// TestConvertSplunk_AgreesWithLegacyhdfOnAbsence is the contract that matters
// here: the two readers of an InSpec control payload must treat an ABSENT field
// identically. They diverged before — Go read absent impact as 0 while TS
// dropped the field entirely — and nothing in the suite would have caught it,
// because no fixture omits the field.
func TestConvertSplunk_AgreesWithLegacyhdfOnAbsence(t *testing.T) {
	const id = "V-1"
	splunkDoc := `[{"meta":{"subtype":"header","filetype":"evaluation","hdf_splunk_schema":"1.0","guid":"g1","filename":"f.json"},"profiles":[],"platform":{"name":"centos","release":"7"},"statistics":{},"version":"4.16.0"},
{"meta":{"subtype":"profile","filetype":"evaluation","hdf_splunk_schema":"1.0","guid":"g1","filename":"f.json","profile_sha256":"abc"},"name":"p","sha256":"abc","controls":[]},
{"meta":{"subtype":"control","filetype":"evaluation","hdf_splunk_schema":"1.0","guid":"g1","filename":"f.json","profile_sha256":"abc"},"id":"` + id + `","title":"t",` +
		`"results":[{"status":"skipped","code_desc":"c","skip_message":"s","start_time":"2026-01-02T03:04:05Z"}]}]`

	legacyDoc := `{"platform":{"name":"centos","release":"7"},"version":"4.16.0","statistics":{},
"profiles":[{"name":"p","sha256":"abc","controls":[{"id":"` + id + `","title":"t",
"results":[{"status":"skipped","code_desc":"c","skip_message":"s","start_time":"2026-01-02T03:04:05Z"}]}]}]}`

	fromSplunk, err := ConvertSplunkToHDF([]byte(splunkDoc), testConverterVersion)
	require.NoError(t, err)
	v1, err := legacyhdf.ParseLegacyHDF([]byte(legacyDoc))
	require.NoError(t, err)
	fromFile := legacyhdf.ConvertLegacyHDF(v1, testConverterVersion)

	pick := func(out *hdf.HDFResults) hdf.EvaluatedRequirement {
		t.Helper()
		for _, b := range out.Baselines {
			for _, r := range b.Requirements {
				if r.ID == id {
					return r
				}
			}
		}
		t.Fatalf("requirement %s missing", id)
		return hdf.EvaluatedRequirement{}
	}

	a, b := pick(fromSplunk), pick(fromFile)
	assert.InDelta(t, b.Impact, a.Impact, 0.0001, "an absent impact must resolve the same in both readers")
	assert.NotNil(t, a.Tags, "neither reader may emit a nil tags map")
	assert.NotNil(t, b.Tags)

	statuses := func(r hdf.EvaluatedRequirement) []hdf.ResultStatus {
		out := make([]hdf.ResultStatus, 0, len(r.Results))
		for _, x := range r.Results {
			out = append(out, x.Status)
		}
		return out
	}
	assert.Equal(t, statuses(b), statuses(a), "and neither may synthesize a result the other does not")
}

// The splunk twin: its resultless control produced results: [], which fails
// minItems:1 rather than the type check, but is the same source-absence defect
// and needs the same synthesized result.
func TestConvertSplunk_ResultlessControlIsSchemaValid(t *testing.T) {
	var events []map[string]interface{}
	require.NoError(t, json.Unmarshal(loadMinimalFixture(t), &events))
	for _, e := range events {
		if meta, ok := e["meta"].(map[string]interface{}); ok && meta["subtype"] == "control" {
			delete(e, "results")
		}
	}
	raw, err := json.Marshal(events)
	require.NoError(t, err)

	out, err := ConvertSplunkToHDF(raw, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, out.Baselines[0].Requirements)
	for _, req := range out.Baselines[0].Requirements {
		require.Len(t, req.Results, 1, "exactly one synthesized result, since minItems is 1")
		assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
		assert.Contains(t, req.Results[0].CodeDesc, "no results for this control",
			"must match the TS peer's assertion, so a wording change cannot pass one side only")
	}

	serialized, err := json.Marshal(out)
	require.NoError(t, err)
	v := validators.Validate(serialized, validators.TypeResults)
	assert.Truef(t, v.Valid, "resultless output must validate: %s", v.Error())
}
