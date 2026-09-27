package oscal

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func TestConvertPOAMToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertPOAMToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertPOAMToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertPOAMToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertPOAMToHDF_NotPOAM(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	_, err = ConvertPOAMToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected plan-of-action-and-milestones document")
}

func TestConvertPOAMToHDF_FedRAMPFixture(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Amendments name from metadata
	assert.NotEmpty(t, amendments.Name)
	assert.Contains(t, amendments.Name, "fedramp")

	// Overrides populated with type "poam"
	assert.NotEmpty(t, amendments.Overrides, "overrides should be populated from poam-items")
	for _, override := range amendments.Overrides {
		assert.Equal(t, hdf.Poam, override.Type, "all overrides should have type 'poam'")
	}

	// systemRef from import-ssp
	assert.NotNil(t, amendments.SystemRef, "systemRef should be set from import-ssp")
	assert.Equal(t, "#7c30125f-c056-4888-9f1a-7ed1b6a1b638", *amendments.SystemRef)

	// Generator
	assert.NotNil(t, amendments.Generator)
	assert.Equal(t, "oscal-poam-to-hdf", amendments.Generator.Name)
	assert.Equal(t, "1.0.0-test", amendments.Generator.Version)

	// Integrity
	assert.NotNil(t, amendments.Integrity)
	assert.Equal(t, hdf.Sha256, *amendments.Integrity.Algorithm)
}

// poamDocWithDeadline builds a minimal valid POA&M whose single item resolves a
// deadline from its related risk. Callers mutate the returned map before
// marshaling to exercise specific paths.
func poamDocWithDeadline() map[string]interface{} {
	return map[string]interface{}{
		"plan-of-action-and-milestones": map[string]interface{}{
			"uuid": "123",
			"metadata": map[string]interface{}{
				"title": "POAM", "version": "1", "oscal-version": "1.1.2",
				"last-modified": "2024-01-01T00:00:00Z",
			},
			"risks": []interface{}{map[string]interface{}{
				"uuid": "r-1", "title": "R", "status": "open",
				"deadline": "2025-01-01T00:00:00Z",
			}},
			"poam-items": []interface{}{map[string]interface{}{
				"uuid": "item-1", "title": "Finding",
				"related-risks": []interface{}{map[string]interface{}{"risk-uuid": "r-1"}},
			}},
		},
	}
}

func TestConvertPOAMToHDF_FailsLoudWithoutDeadline(t *testing.T) {
	doc := poamDocWithDeadline()
	// Remove the deadline so no time commitment is derivable.
	poam := doc["plan-of-action-and-milestones"].(map[string]interface{})
	poam["risks"].([]interface{})[0].(map[string]interface{})["deadline"] = ""
	input, err := json.Marshal(doc)
	require.NoError(t, err)

	_, err = ConvertPOAMToHDF(input, "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a time commitment")
}

func TestConvertPOAMToHDF_FailsLoudInvalidLastModified(t *testing.T) {
	doc := poamDocWithDeadline()
	poam := doc["plan-of-action-and-milestones"].(map[string]interface{})
	poam["metadata"].(map[string]interface{})["last-modified"] = "not-a-date"
	input, err := json.Marshal(doc)
	require.NoError(t, err)

	_, err = ConvertPOAMToHDF(input, "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata.last-modified")
}

func TestConvertPOAMToHDF_ExtractsRealDates(t *testing.T) {
	doc := poamDocWithDeadline()
	poam := doc["plan-of-action-and-milestones"].(map[string]interface{})
	risk := poam["risks"].([]interface{})[0].(map[string]interface{})
	risk["remediations"] = []interface{}{
		map[string]interface{}{
			"lifecycle": "planned", "title": "Fix", "description": "Apply patch",
			"tasks": []interface{}{map[string]interface{}{
				"uuid": "t1", "type": "milestone", "title": "Patch step",
				"timing": map[string]interface{}{
					"within-date-range": map[string]interface{}{
						"start": "2024-06-01T00:00:00Z", "end": "2024-06-15T00:00:00Z",
					},
				},
			}},
		},
		map[string]interface{}{"lifecycle": "completed", "title": "Done", "description": "Already fixed"},
	}
	input, err := json.Marshal(doc)
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, amendments.Overrides, 1)

	override := amendments.Overrides[0]
	assert.Equal(t, "2025-01-01T00:00:00Z", override.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, "2024-01-01T00:00:00Z", override.AppliedAt.UTC().Format("2006-01-02T15:04:05Z"))
	require.Len(t, override.Milestones, 1, "only the planned remediation's task becomes a milestone")
	assert.Equal(t, "Patch step", override.Milestones[0].Description)
	assert.Equal(t, "2024-06-15T00:00:00Z", override.Milestones[0].EstimatedCompletion.UTC().Format("2006-01-02T15:04:05Z"))
}

func TestConvertPOAMToHDF_AmendmentsNameFromMetadata(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Title: "[System Name] FedRAMP Plan of Action and Milestones (POA&M)"
	assert.Contains(t, amendments.Name, "system-name")
	assert.Contains(t, amendments.Name, "plan-of-action-and-milestones")
}

func TestConvertPOAMToHDF_OverridesHaveRequirementIDs(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, amendments.Overrides)

	// First poam-item is related to risk with impacted-control-id "ac-2"
	// which should map to "AC-2"
	assert.Equal(t, "AC-2", amendments.Overrides[0].RequirementID)
}

func TestConvertPOAMToHDF_OverridesHaveReasons(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	for _, override := range amendments.Overrides {
		assert.NotEmpty(t, override.Reason, "every override should have a reason")
	}
}

func TestConvertPOAMToHDF_RiskSeverityExtracted(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// The fixture has risks with "open" status → should map to "failed"
	require.NotEmpty(t, amendments.Overrides)
	require.NotNil(t, amendments.Overrides[0].Status)
	assert.Equal(t, hdf.Failed, *amendments.Overrides[0].Status)
}

func TestConvertPOAMToHDF_ValidatesAgainstSchema(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/poam-fedramp.json")
	require.NoError(t, err)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Verify it marshals to valid JSON
	out, err := json.Marshal(amendments)
	require.NoError(t, err)

	// Verify it unmarshals back cleanly
	var roundtrip hdf.HDFAmendments
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, amendments.Name, roundtrip.Name)
	assert.Equal(t, len(amendments.Overrides), len(roundtrip.Overrides))
}

func TestPoamAmendmentsName(t *testing.T) {
	tests := []struct {
		title    string
		expected string
	}{
		{"FedRAMP POA&M Title", "fedramp-poa-m-title"},
		{"Simple Title", "simple-title"},
		{"", "oscal-poam"},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			assert.Equal(t, tt.expected, ToKebabCase(tt.title, "oscal-poam"))
		})
	}
}

// TestConvertPOAMToHDF_PreADRDocument reads a pre-ADR HDF POA&M through the pre-ADR
// mapping (ADR-0014 §4.3): its risks carry override-type without ns, so none is
// HDF-produced, and every override imports as the v3.6.0 importer read it, except
// that an item with no impacted-control-id is skipped with a warning rather than
// named by its title or "unknown".
//
// testdata/provenance.txt records how hdf-cli v3.6.0 produced the fixture and the
// oracle from testdata/poam-pre-adr.v3.6.0-input.json.
func TestConvertPOAMToHDF_PreADRDocument(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	input, err := os.ReadFile(filepath.Join("testdata", "poam-pre-adr.json"))
	require.NoError(t, err)
	validator := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))
	validator.RequireValid(t, "pre-ADR POA&M", input)

	amendments, err := ConvertPOAMToHDF(input, "1.0.0")
	require.NoError(t, err)
	got, err := json.Marshal(amendments)
	require.NoError(t, err)
	assert.Contains(t, logs.String(), `WARNING: Skipping poam-item "6f81f9fe-06ff-418f-b294-04e613bad22d" titled "": its pre-ADR risk has no impacted-control-id`)

	released, err := os.ReadFile(filepath.Join("testdata", "poam-pre-adr.v3.6.0-import.json"))
	require.NoError(t, err)
	want := preADRComparable(t, released)
	overrides := want["overrides"].([]any)
	require.Equal(t, "unknown", overrides[len(overrides)-1].(map[string]any)["requirementId"], "the released importer named the id-less item unknown")
	want["overrides"] = overrides[:len(overrides)-1]
	assert.Equal(t, want, preADRComparable(t, got))

	logs.Reset()
	count, _, err := ExpectedPOAMRequirementCount(input)
	require.NoError(t, err)
	assert.Equal(t, len(amendments.Overrides), count, "the count agrees with the skip")
	assert.Empty(t, logs.String(), "the count path skips silently")
}

// captureLogs redirects the standard logger for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &logs
}

// An observation a foreign tool added to an HDF-produced item's
// related-observations carries no Evidence.data, which HDF requires non-empty.
func TestItemEvidence_SkipsObservationWithNoPayload(t *testing.T) {
	logs := captureLogs(t)

	poam := &PlanOfActionAndMilestones{
		Observations: []Observation{
			{UUID: "obs-bare", Description: "Reviewed the change ticket", Types: []string{"url"}, Collected: "2026-01-02T03:04:05Z"},
			{UUID: "obs-dangling", Types: []string{"file"}, Links: []Link{{Href: "#missing", Rel: "evidence"}}},
			{UUID: "obs-href", Types: []string{"url"}, RelevantEvidence: []RelevantEvidence{{Href: "https://example.com/advisory"}}},
		},
	}
	item := &POAMItem{RelatedObservations: []RelatedRef{
		{ObservationUUID: "obs-bare"}, {ObservationUUID: "obs-dangling"}, {ObservationUUID: "obs-href"},
	}}

	evidence := itemEvidence(item, poam)

	require.Len(t, evidence, 1, "only the observation carrying a payload is evidence")
	assert.Equal(t, "https://example.com/advisory", evidence[0].Data)
	assert.Contains(t, logs.String(), `WARNING: Skipping evidence observation "obs-bare": no relevant-evidence href and no evidence resource`)
	assert.Contains(t, logs.String(), `WARNING: Skipping evidence observation "obs-dangling": no relevant-evidence href and no evidence resource`)
}

// A foreign task title need not be the single line HDF's Milestone.title is.
func TestHDFMilestones_DropsATitleHDFCannotCarry(t *testing.T) {
	logs := captureLogs(t)

	task := func(uuid, title string) Task {
		return Task{UUID: uuid, Title: title, Timing: &Timing{WithinDateRange: &DateRange{End: "2099-12-31T00:00:00Z"}}}
	}
	risk := &Risk{Remediations: []Remediation{{Lifecycle: "planned", Description: "Patch the web tier", Tasks: []Task{
		task("t-ok", "Deploy OpenSSH 9.8p1"),
		task("t-empty", ""),
		task("t-space", " leading space"),
		task("t-wrapped", "two\nlines"),
	}}}}

	milestones := hdfMilestones(risk, &PlanOfActionAndMilestones{})

	require.Len(t, milestones, 4, "the milestone is kept; only the title HDF cannot carry is dropped")
	require.NotNil(t, milestones[0].Title)
	assert.Equal(t, "Deploy OpenSSH 9.8p1", *milestones[0].Title)
	for _, ms := range milestones[1:] {
		assert.Nil(t, ms.Title)
		assert.Equal(t, "Patch the web tier", ms.Description)
	}
	assert.Contains(t, logs.String(), `WARNING: Dropping the title of task "t-empty": ""`)
	assert.Contains(t, logs.String(), `WARNING: Dropping the title of task "t-space": " leading space"`)
	assert.Contains(t, logs.String(), `WARNING: Dropping the title of task "t-wrapped": "two\nlines"`)
}

// An HDF-produced risk whose hdf-requirement-id was stripped names no
// requirement, and StandaloneOverride.requirementId must be non-empty.
func TestPoamItemToOverride_SkipsHDFProducedRiskWithNoRequirementID(t *testing.T) {
	logs := captureLogs(t)

	poam := &PlanOfActionAndMilestones{
		Metadata: Metadata{LastModified: "2026-01-02T03:04:05Z"},
		Risks: []Risk{{
			UUID:     "r1",
			Deadline: "2099-12-31T00:00:00Z",
			Props:    []Property{{Name: "override-type", Ns: hdfNS, Value: "waiver"}},
		}},
	}
	item := &POAMItem{UUID: "i1", Title: "Some item", RelatedRisks: []RelatedRef{{RiskUUID: "r1"}}}
	riskMap := buildRiskMap(poam.Risks)

	_, identified, err := poamItemToOverride(item, riskMap, poam)

	require.NoError(t, err)
	assert.False(t, identified)
	assert.Contains(t, logs.String(), `WARNING: Skipping poam-item "i1" titled "Some item": its HDF-produced risk has no hdf-requirement-id`)

	logs.Reset()
	assert.False(t, identifiedItem(item, riskMap), "the fidelity count agrees with the skip")
	assert.Empty(t, logs.String(), "the count path skips silently")
}

// HDFAmendments.overrides is required and non-empty, so a POA&M whose every item
// is skipped is a failed conversion, not an empty success.
func TestConvertPOAMToHDF_FailsWhenNoItemNamesARequirement(t *testing.T) {
	captureLogs(t)

	input, err := json.Marshal(map[string]any{"plan-of-action-and-milestones": map[string]any{
		"uuid":     "11111111-1111-4111-8111-111111111111",
		"metadata": map[string]any{"title": "Nothing to import", "last-modified": "2026-01-02T03:04:05Z", "version": "1.0", "oscal-version": "1.1.2"},
		"risks": []any{map[string]any{
			"uuid": "r1", "title": "r", "description": "d", "status": "open", "deadline": "2099-12-31T00:00:00Z",
			"props": []any{map[string]any{"name": "override-type", "ns": hdfNS, "value": "waiver"}},
		}},
		"poam-items": []any{map[string]any{
			"uuid": "i1", "title": "Some item", "description": "d",
			"related-risks": []any{map[string]any{"risk-uuid": "r1"}},
		}},
	}})
	require.NoError(t, err)

	_, err = ConvertPOAMToHDF(input, "1.0.0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no poam-item names a requirement")
}

// preADRComparable decodes an amendments document without the fields a converter
// stamps or derives from bytes the comparison does not share: generator,
// integrity and each override's previousChecksum.
func preADRComparable(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	delete(doc, "generator")
	delete(doc, "integrity")
	for _, o := range doc["overrides"].([]any) {
		delete(o.(map[string]any), "previousChecksum")
	}
	return doc
}
