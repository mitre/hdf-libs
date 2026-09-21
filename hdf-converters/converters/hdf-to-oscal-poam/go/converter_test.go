package hdftooscalpoam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resultStatusPtr(s hdf.ResultStatus) *hdf.ResultStatus { return &s }

func TestConvertHDFToOSCALPOAM_EmptyInput(t *testing.T) {
	_, err := ConvertHDFToOSCALPOAM([]byte{}, "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertHDFToOSCALPOAM_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToOSCALPOAM([]byte(`{not json`), "1.0.0")
	require.Error(t, err)
	// Wording comes from the shared guard, which hdf-to-oscal-sar and exportmap
	// already emit — this converter previously said "failed to parse JSON".
	assert.Contains(t, err.Error(), "failed to parse HDF JSON")
}

func TestConvertHDFToOSCALPOAM_MinimalAmendments(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "test-poam",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-1",
				Reason:        "Pending remediation",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin@example.com",
				},
				AppliedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)
	require.NotNil(t, doc.PlanOfActionAndMilestones)

	poam := doc.PlanOfActionAndMilestones

	// Verify metadata
	assert.Equal(t, "test-poam", poam.Metadata.Title)
	assert.Equal(t, "1.0.0", poam.Metadata.Version)
	assert.Equal(t, "1.1.2", poam.Metadata.OscalVersion)
	assert.NotEmpty(t, poam.Metadata.LastModified)

	// Verify UUID is set
	assert.NotEmpty(t, poam.UUID)
	assert.Len(t, poam.UUID, 36) // UUID format: 8-4-4-4-12

	// Verify import-ssp defaults to "#"
	require.NotNil(t, poam.ImportSSP)
	assert.Equal(t, "#", poam.ImportSSP.Href)

	// Verify poam-items
	require.Len(t, poam.POAMItems, 1)
	item := poam.POAMItems[0]
	assert.NotEmpty(t, item.UUID)
	assert.Equal(t, "AC-1", item.Title)
	assert.Equal(t, "Pending remediation", item.Description)

	// Verify related risks
	require.Len(t, item.RelatedRisks, 1)
	assert.NotEmpty(t, item.RelatedRisks[0].RiskUUID)

	// Verify risk
	require.Len(t, poam.Risks, 1)
	risk := poam.Risks[0]
	assert.Equal(t, item.RelatedRisks[0].RiskUUID, risk.UUID)
	assert.Equal(t, "open", risk.Status)
	assert.Equal(t, "Pending remediation", risk.Description)
}

func TestConvertHDFToOSCALPOAM_SystemRef(t *testing.T) {
	sysRef := "https://example.com/ssp.json"
	amendments := hdf.HDFAmendments{
		Name:      "test-poam",
		SystemRef: &sysRef,
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-1",
				Reason:        "test",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com/ssp.json", doc.PlanOfActionAndMilestones.ImportSSP.Href)
}

func TestConvertHDFToOSCALPOAM_StatusMapping(t *testing.T) {
	tests := []struct {
		hdfStatus   hdf.ResultStatus
		oscalStatus string
	}{
		{hdf.Passed, "closed"},
		{hdf.Failed, "open"},
		{hdf.Error, "open"},
		{hdf.NotApplicable, "closed"},
		{hdf.NotReviewed, "open"},
	}

	for _, tt := range tests {
		t.Run(string(tt.hdfStatus), func(t *testing.T) {
			amendments := hdf.HDFAmendments{
				Name: "status-test",
				Overrides: []hdf.StandaloneOverride{
					{
						Type:          hdf.Poam,
						RequirementID: "AC-1",
						Reason:        "test",
						Status:        &tt.hdfStatus,
						AppliedBy: hdf.Identity{
							Type:       hdf.Simple,
							Identifier: "admin",
						},
						AppliedAt: time.Now(),
						ExpiresAt: time.Now().AddDate(1, 0, 0),
					},
				},
			}

			input, err := json.Marshal(amendments)
			require.NoError(t, err)

			output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)

			var doc oscal.OscalDocument
			err = json.Unmarshal(output, &doc)
			require.NoError(t, err)

			require.Len(t, doc.PlanOfActionAndMilestones.Risks, 1)
			assert.Equal(t, tt.oscalStatus, doc.PlanOfActionAndMilestones.Risks[0].Status)
		})
	}
}

func TestConvertHDFToOSCALPOAM_MultipleOverrides(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "multi-test",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-1",
				Reason:        "First item",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
			},
			{
				Type:          hdf.Poam,
				RequirementID: "SI-7 (1)",
				Reason:        "Second item",
				Status:        resultStatusPtr(hdf.Passed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)

	poam := doc.PlanOfActionAndMilestones
	require.Len(t, poam.POAMItems, 2)
	require.Len(t, poam.Risks, 2)

	// Verify each item has unique UUID
	assert.NotEqual(t, poam.POAMItems[0].UUID, poam.POAMItems[1].UUID)

	// Verify control ID conversion in risk props
	assert.Equal(t, "AC-1", poam.POAMItems[0].Title)
	assert.Equal(t, "SI-7 (1)", poam.POAMItems[1].Title)

	// Each risk carries the exact requirement id and the FedRAMP impacted control in OSCAL form.
	for i, want := range []struct{ requirementID, control string }{{"AC-1", "ac-1"}, {"SI-7 (1)", "si-7.1"}} {
		id, ok := oscal.FindVocabularyProp(poam.Risks[i].Props, "hdf-requirement-id")
		require.True(t, ok)
		assert.Equal(t, want.requirementID, id.Value)
		control, ok := oscal.FindVocabularyProp(poam.Risks[i].Props, "impacted-control-id")
		require.True(t, ok)
		assert.Equal(t, want.control, control.Value)
	}
}

func TestConvertHDFToOSCALPOAM_Milestones(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "milestone-test",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-2",
				Reason:        "With milestones",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
				Milestones: []hdf.Milestone{
					{
						Title:               strPtr("Deploy MFA"),
						Description:         "Deploy MFA solution",
						EstimatedCompletion: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
						Status:              hdf.Pending,
					},
					{
						Title:               strPtr("Verify MFA"),
						Description:         "Verify MFA deployment",
						EstimatedCompletion: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
						Status:              hdf.InProgress,
					},
				},
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)

	require.Len(t, doc.PlanOfActionAndMilestones.Risks, 1)
	risk := doc.PlanOfActionAndMilestones.Risks[0]
	require.Len(t, risk.Remediations, 2)

	assert.Equal(t, "planned", risk.Remediations[0].Lifecycle)
	assert.Equal(t, "Deploy MFA", risk.Remediations[0].Title)
	assert.Equal(t, "Verify MFA", risk.Remediations[1].Title)
}

func TestConvertHDFToOSCALPOAM_FieldCoverage(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Overrides: []hdf.StandaloneOverride{{
			Type:          hdf.RiskAdjustment,
			RequirementID: "AC-1",
			Reason:        "residual risk accepted",
			Status:        resultStatusPtr(hdf.Failed),
			Impact:        &hdf.ImpactOverride{Value: 0.3},
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
			AppliedAt:     time.Now(),
			Milestones: []hdf.Milestone{{
				Description:         "apply patch",
				EstimatedCompletion: time.Date(2099, 6, 30, 0, 0, 0, 0, time.UTC),
				Status:              hdf.Pending,
			}},
		}},
	}
	input, err := json.Marshal(amendments)
	require.NoError(t, err)
	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	require.NoError(t, json.Unmarshal(output, &doc))
	risk := doc.PlanOfActionAndMilestones.Risks[0]

	prop := func(props []oscal.Property, name string) string {
		for _, p := range props {
			if p.Name == name {
				return p.Value
			}
		}
		return ""
	}
	assert.Equal(t, "riskAdjustment", prop(risk.Props, "override-type"))
	assert.Equal(t, "failed", prop(risk.Props, "override-status"))
	assert.Equal(t, "0.3", prop(risk.Props, "impact-override"))
	require.NotEmpty(t, risk.Remediations)
	rem := risk.Remediations[0]
	assert.Equal(t, "apply patch", rem.Description)
	require.NotEmpty(t, rem.Tasks, "milestone should emit a remediation task")
	require.NotNil(t, rem.Tasks[0].Timing)
	require.NotNil(t, rem.Tasks[0].Timing.WithinDateRange)
	assert.Contains(t, rem.Tasks[0].Timing.WithinDateRange.End, "2099-06-30")
	assert.Equal(t, "pending", prop(rem.Tasks[0].Props, "milestone-status"))
	_, onRemediation := propVal(rem.Props, "milestone-status")
	assert.False(t, onRemediation, "the milestone status rides on the task")
}

func TestConvertHDFToOSCALPOAM_AppliedByInMetadata(t *testing.T) {
	appliedBy := &hdf.Identity{
		Type:       hdf.Simple,
		Identifier: "security-team@example.com",
	}
	amendments := hdf.HDFAmendments{
		Name:      "applied-by-test",
		AppliedBy: appliedBy,
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-1",
				Reason:        "test",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)

	meta := doc.PlanOfActionAndMilestones.Metadata
	require.Len(t, meta.ResponsibleParties, 1)
	assert.Equal(t, "prepared-by", meta.ResponsibleParties[0].RoleID)
	// Document applier is party[0]; the distinct per-override applier is surfaced too.
	require.Len(t, meta.Parties, 2)
	assert.Equal(t, "security-team@example.com", meta.Parties[0].Name)
	assert.Equal(t, meta.Parties[0].UUID, meta.ResponsibleParties[0].PartyIDs[0])
	names := map[string]bool{meta.Parties[0].Name: true, meta.Parties[1].Name: true}
	assert.True(t, names["admin"], "per-override applier should be a party")
}

func TestConvertHDFToOSCALPOAM_ExpiresAtInRiskLog(t *testing.T) {
	expiresAt := time.Date(2027, 3, 15, 12, 0, 0, 0, time.UTC)
	amendments := hdf.HDFAmendments{
		Name: "expires-test",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-1",
				Reason:        "test",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: expiresAt,
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)

	risk := doc.PlanOfActionAndMilestones.Risks[0]
	require.NotNil(t, risk.RiskLog)
	require.Len(t, risk.RiskLog.Entries, 2)
	assert.Equal(t, "Override applied", risk.RiskLog.Entries[0].Title)
	assert.Equal(t, "Scheduled review", risk.RiskLog.Entries[1].Title)
	assert.Equal(t, "2027-03-15T12:00:00Z", risk.RiskLog.Entries[1].Start)
	assert.Equal(t, "2027-03-15T12:00:00Z", risk.Deadline)
}

func TestConvertHDFToOSCALPOAM_UniqueUUIDs(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "uuid-test",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-1",
				Reason:        "test 1",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
			},
			{
				Type:          hdf.Poam,
				RequirementID: "AC-2",
				Reason:        "test 2",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "admin",
				},
				AppliedAt: time.Now(),
				ExpiresAt: time.Now().AddDate(1, 0, 0),
			},
		},
	}

	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	output, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc oscal.OscalDocument
	err = json.Unmarshal(output, &doc)
	require.NoError(t, err)

	// Collect all UUIDs to verify uniqueness
	uuids := make(map[string]bool)
	poam := doc.PlanOfActionAndMilestones

	uuids[poam.UUID] = true
	for _, item := range poam.POAMItems {
		assert.False(t, uuids[item.UUID], "duplicate UUID: %s", item.UUID)
		uuids[item.UUID] = true
	}
	for _, risk := range poam.Risks {
		assert.False(t, uuids[risk.UUID], "duplicate UUID: %s", risk.UUID)
		uuids[risk.UUID] = true
	}
}

func TestNistTagToControlID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AC-1", "ac-1"},
		{"AC-2 (3)", "ac-2.3"},
		{"SI-7 (1)", "si-7.1"},
		{"ac-1", "ac-1"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, oscal.NistTagToControlID(tt.input))
		})
	}
}

func TestHdfStatusToOSCAL(t *testing.T) {
	assert.Equal(t, "closed", oscal.HDFStatusToOSCALRiskStatus(hdf.Passed))
	assert.Equal(t, "open", oscal.HDFStatusToOSCALRiskStatus(hdf.Failed))
	assert.Equal(t, "open", oscal.HDFStatusToOSCALRiskStatus(hdf.Error))
	assert.Equal(t, "closed", oscal.HDFStatusToOSCALRiskStatus(hdf.NotApplicable))
	assert.Equal(t, "open", oscal.HDFStatusToOSCALRiskStatus(hdf.NotReviewed))
}

func TestGenerateUUID(t *testing.T) {
	uuid1 := oscal.GenerateUUID()
	uuid2 := oscal.GenerateUUID()

	// Should be proper UUID format
	assert.Len(t, uuid1, 36)
	assert.Contains(t, uuid1, "-")

	// Should be unique
	assert.NotEqual(t, uuid1, uuid2)

	// Verify version 4 marker (character at position 14 should be '4')
	assert.Equal(t, byte('4'), uuid1[14])
}

// roundTripCases is the shared ADR-0014 §4.6 round-trip case table the
// TypeScript suite also reads.
type roundTripCases struct {
	Excluded struct {
		Document []string `json:"document"`
		Override []string `json:"override"`
	} `json:"excluded"`
	Cases []struct {
		Name       string          `json:"name"`
		Amendments json.RawMessage `json:"amendments"`
	} `json:"cases"`
}

func loadRoundTripCases(t *testing.T) roundTripCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "..", "shared", "oscal-poam-roundtrip-cases.json"))
	require.NoError(t, err)
	var table roundTripCases
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)
	return table
}

// withoutExcluded decodes an amendments document and deletes the fields the
// round-trip contract excludes.
func withoutExcluded(t *testing.T, raw []byte, table roundTripCases) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	for _, k := range table.Excluded.Document {
		delete(doc, k)
	}
	overrides, _ := doc["overrides"].([]any)
	for _, o := range overrides {
		for _, k := range table.Excluded.Override {
			delete(o.(map[string]any), k)
		}
	}
	return doc
}

// assertSameFields compares two JSON objects key by key, so a failure names the field.
func assertSameFields(t *testing.T, path string, want, got map[string]any) {
	t.Helper()
	keys := map[string]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	for k := range keys {
		wantV, inWant := want[k]
		gotV, inGot := got[k]
		switch {
		case !inWant:
			t.Errorf("%s.%s: not in the source, but came back as %v", path, k, gotV)
		case !inGot:
			t.Errorf("%s.%s: lost (source %v)", path, k, wantV)
		default:
			assert.Equal(t, wantV, gotV, "%s.%s", path, k)
		}
	}
}

// TestConvertHDFToOSCALPOAM_RoundTrip asserts the ADR-0014 §4.6 contract: HDF
// amendments → OSCAL POA&M → HDF returns every field exactly, and the contract's
// exclusions are the only differences.
func TestConvertHDFToOSCALPOAM_RoundTrip(t *testing.T) {
	table := loadRoundTripCases(t)
	hdfV := amendmentsValidator(t)
	schemas := poamSchemas(t)
	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			require.NoError(t, hdfV.Validate(tc.Amendments), "the case is not valid HDF")

			poam, err := ConvertHDFToOSCALPOAM(tc.Amendments, "1.0.0")
			require.NoError(t, err)
			for _, s := range schemas {
				s.v.RequireValid(t, s.file, poam)
			}

			back, err := oscal.ConvertPOAMToHDF(poam, "1.0.0")
			require.NoError(t, err)
			out, err := json.Marshal(back)
			require.NoError(t, err)

			want := withoutExcluded(t, tc.Amendments, table)
			got := withoutExcluded(t, out, table)
			wantOverrides, _ := want["overrides"].([]any)
			gotOverrides, _ := got["overrides"].([]any)
			delete(want, "overrides")
			delete(got, "overrides")
			assertSameFields(t, "document", want, got)
			require.Len(t, gotOverrides, len(wantOverrides))
			for i := range wantOverrides {
				assertSameFields(t, fmt.Sprintf("overrides[%d]", i), wantOverrides[i].(map[string]any), gotOverrides[i].(map[string]any))
			}
		})
	}
}

// TestRoundTripCases_SchemaExamples pins the first case to the Standalone_Override
// schema examples, so the table cannot drift from the schema it claims to reproduce.
func TestRoundTripCases_SchemaExamples(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "..", "..", "hdf-schema", "src", "schemas", "primitives", "amendments.schema.json"))
	require.NoError(t, err)
	var schema struct {
		Defs struct {
			StandaloneOverride struct {
				Examples []any `json:"examples"`
			} `json:"Standalone_Override"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	require.Len(t, schema.Defs.StandaloneOverride.Examples, 7)

	var first struct {
		Overrides []any `json:"overrides"`
	}
	require.NoError(t, json.Unmarshal(loadRoundTripCases(t).Cases[0].Amendments, &first))
	assert.Equal(t, schema.Defs.StandaloneOverride.Examples, first.Overrides)
}

// hdfSchemaDefs merges the $defs of the source schemas an amendments document
// draws on, with the document itself under "", so a $ref resolves by def name.
func hdfSchemaDefs(t *testing.T) map[string]map[string]any {
	t.Helper()
	dir := filepath.Join(shared.GetConvertersDir(), "..", "..", "hdf-schema", "src", "schemas")
	defs := map[string]map[string]any{}
	for _, f := range []string{"hdf-amendments.schema.json", "primitives/amendments.schema.json",
		"primitives/common.schema.json", "primitives/affected-package.schema.json", "primitives/cvss.schema.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		require.NoError(t, err)
		var schema map[string]any
		require.NoError(t, json.Unmarshal(raw, &schema))
		if f == "hdf-amendments.schema.json" {
			defs[""] = schema
		}
		schemaDefs, _ := schema["$defs"].(map[string]any)
		for name, def := range schemaDefs {
			defs[name] = def.(map[string]any)
		}
	}
	return defs
}

// schemaHasProperty reports whether a dot-separated JSON property path names a
// property of the def, following $ref and array items by def name.
func schemaHasProperty(defs map[string]map[string]any, def, path string) bool {
	node := defs[def]
	for _, name := range strings.Split(path, ".") {
		props, _ := node["properties"].(map[string]any)
		next, ok := props[name].(map[string]any)
		if !ok {
			return false
		}
		if items, ok := next["items"].(map[string]any); ok {
			next = items
		}
		if ref, ok := next["$ref"].(string); ok {
			next = defs[ref[strings.LastIndex(ref, "/")+1:]]
		}
		node = next
	}
	return true
}

// markerContexts maps the OSCAL object that carries an empty-field or absent-field
// marker to the HDF def whose fields it names; a group maps to its prop group.
var markerContexts = []struct {
	path  *regexp.Regexp
	group *regexp.Regexp
	def   string
}{
	{regexp.MustCompile(`^metadata$`), regexp.MustCompile(`^$`), ""},
	{regexp.MustCompile(`^metadata$`), regexp.MustCompile(`^label-[1-9][0-9]*$`), "label"},
	{regexp.MustCompile(`^metadata\.parties\[\d+\]$`), regexp.MustCompile(`^$`), "Identity"},
	{regexp.MustCompile(`^risks\[\d+\]$`), regexp.MustCompile(`^$`), "Standalone_Override"},
	{regexp.MustCompile(`^risks\[\d+\]$`), regexp.MustCompile(`^package-[1-9][0-9]*$`), "Affected_Package"},
	{regexp.MustCompile(`^risks\[\d+\]\.characterizations\[\d+\]$`), regexp.MustCompile(`^$`), "Cvss"},
	{regexp.MustCompile(`^risks\[\d+\]\.remediations\[\d+\](\.tasks\[\d+\])?$`), regexp.MustCompile(`^$`), "Milestone"},
	{regexp.MustCompile(`^observations\[\d+\]$`), regexp.MustCompile(`^$`), "Evidence"},
	{regexp.MustCompile(`^back-matter\.resources\[\d+\]$`), regexp.MustCompile(`^$`), "External_Reference"},
}

// fieldMarker is an empty-field or absent-field prop and the object that carries it.
type fieldMarker struct{ path, group, field string }

// collectFieldMarkers walks a decoded POA&M and returns every HDF field marker.
func collectFieldMarkers(node any, path string, out *[]fieldMarker) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if k != "props" {
				collectFieldMarkers(child, strings.TrimPrefix(path+"."+k, "."), out)
				continue
			}
			for _, p := range child.([]any) {
				prop := p.(map[string]any)
				if (prop["name"] == "empty-field" || prop["name"] == "absent-field") && prop["ns"] == oscal.VocabularyNamespace() {
					group, _ := prop["group"].(string)
					*out = append(*out, fieldMarker{path, group, prop["value"].(string)})
				}
			}
		}
	case []any:
		for i, child := range v {
			collectFieldMarkers(child, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// TestConvertHDFToOSCALPOAM_FieldMarkersNameHDFProperties asserts ADR-0014 §1.7.5
// over every round-trip case: each empty-field and absent-field value is an HDF
// JSON property name, dot-separated relative to the object carrying the marker,
// or the field within the marker's prop group.
func TestConvertHDFToOSCALPOAM_FieldMarkersNameHDFProperties(t *testing.T) {
	defs := hdfSchemaDefs(t)
	seen := map[string]bool{}
	for _, tc := range loadRoundTripCases(t).Cases {
		out, err := ConvertHDFToOSCALPOAM(tc.Amendments, "1.0.0")
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(out, &doc))
		var markers []fieldMarker
		collectFieldMarkers(doc["plan-of-action-and-milestones"], "", &markers)
		for _, m := range markers {
			matched := false
			for _, c := range markerContexts {
				if !c.path.MatchString(m.path) || !c.group.MatchString(m.group) {
					continue
				}
				matched = true
				seen[c.def] = true
				if c.def == "label" {
					assert.Contains(t, []string{"key", "value"}, m.field, "%s: %s at %s", tc.Name, m.group, m.path)
				} else {
					assert.True(t, schemaHasProperty(defs, c.def, m.field), "%s: %q at %s is not a %s property", tc.Name, m.field, m.path, c.def)
				}
			}
			assert.True(t, matched, "%s: a marker at %s (group %q) has no HDF context", tc.Name, m.path, m.group)
		}
	}
	assert.Equal(t, map[string]bool{"": true, "label": true, "Identity": true, "Standalone_Override": true,
		"Affected_Package": true, "Milestone": true, "Evidence": true, "External_Reference": true}, seen,
		"the round-trip cases must exercise a marker in every context they can")
}

// Only the metadata timestamp carries the conversion moment; every other date
// in a POA&M (milestone deadlines, expiration) is input-derived and stays asserted.
var poamVolatileKeys = []string{"last-modified"}

// TestGoldenParity asserts whole-output equality against a frozen golden.
// The TypeScript test asserts against the SAME file, guaranteeing TS↔Go parity.
// Fresh UUIDs and the conversion timestamp are masked (see shared.MaskVolatileJSON) —
// the UUID reference graph survives masking, so wiring differences still fail.
func TestGoldenParity(t *testing.T) {
	out, err := ConvertHDFToOSCALPOAM(fixtures.Amendments.UC01Fixed, "1.0.0")
	require.NoError(t, err)

	goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-poam", "fixtures", "expected", "uc-01-fixed.oscal-poam.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
		return
	}

	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "read golden %s", goldenPath)

	maskedGolden, err := shared.MaskVolatileJSON(golden, poamVolatileKeys)
	require.NoError(t, err)
	maskedOut, err := shared.MaskVolatileJSON(out, poamVolatileKeys)
	require.NoError(t, err)

	assert.Equal(t, maskedGolden, maskedOut, "golden mismatch for uc-01-fixed.oscal-poam.json")
}

// TestConvertHDFToOSCALPOAM_NISTRequirementIDImpactedControl pins the control id
// a NIST requirement id produces in any spelling. A statement-part id names its
// control, since impacted-control-id takes only the control form, and an id NIST
// does not define (including a control-shaped one) produces none.
func TestConvertHDFToOSCALPOAM_NISTRequirementIDImpactedControl(t *testing.T) {
	cases := []struct {
		requirementID string
		want          string
	}{
		{"AC-2 (3)", "ac-2.3"},
		{"ac-2 (3)", "ac-2.3"},
		{"Ac-2(3)", "ac-2.3"},
		{"AC-02 03", "ac-2.3"},
		{"AC-8 c 1", "ac-8"},
		{"AC-2 (3) (a)", "ac-2.3"},
		{"Si-2", "si-2"},
		{"AC-99", ""},
		{"SV-257778", ""},
		{"CVE-2021-44228", ""},
	}
	schemas := poamSchemas(t)
	for _, tc := range cases {
		t.Run(tc.requirementID, func(t *testing.T) {
			input := minimalAmendments(t, map[string]any{"requirementId": tc.requirementID})
			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)

			var doc struct {
				POAM oscal.PlanOfActionAndMilestones `json:"plan-of-action-and-milestones"`
			}
			require.NoError(t, json.Unmarshal(out, &doc))
			require.Len(t, doc.POAM.Risks, 1)
			var got []string
			for _, m := range oscal.FindVocabularyProps(doc.POAM.Risks[0].Props, "impacted-control-id") {
				assert.Equal(t, "https://fedramp.gov/ns/oscal", doc.POAM.Risks[0].Props[m.Index].Ns)
				got = append(got, m.Value)
			}
			var want []string
			if tc.want != "" {
				want = []string{tc.want}
			}
			assert.Equal(t, want, got)

			for _, s := range schemas {
				s.v.RequireValid(t, s.file, out)
			}
		})
	}
}
