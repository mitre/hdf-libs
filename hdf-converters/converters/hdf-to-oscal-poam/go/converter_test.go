package hdftooscalpoam

import (
	"encoding/json"
	"testing"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
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
	assert.Contains(t, err.Error(), "failed to parse JSON")
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

	// Verify risk props contain impacted-control-id in OSCAL format (first prop)
	require.NotEmpty(t, poam.Risks[0].Props)
	assert.Equal(t, "impacted-control-id", poam.Risks[0].Props[0].Name)
	assert.Equal(t, "ac-1", poam.Risks[0].Props[0].Value)

	require.NotEmpty(t, poam.Risks[1].Props)
	assert.Equal(t, "impacted-control-id", poam.Risks[1].Props[0].Name)
	assert.Equal(t, "si-7.1", poam.Risks[1].Props[0].Value)
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
						Description:         "Deploy MFA solution",
						EstimatedCompletion: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
						Status:              hdf.Pending,
					},
					{
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
	assert.Equal(t, "Deploy MFA solution", risk.Remediations[0].Title)
	assert.Equal(t, "Verify MFA deployment", risk.Remediations[1].Title)
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
	assert.Equal(t, "0.3", prop(risk.Props, "impact-override"))
	require.NotEmpty(t, risk.Remediations)
	rem := risk.Remediations[0]
	assert.Contains(t, prop(rem.Props, "estimated-completion"), "2099-06-30")
	assert.Equal(t, "pending", prop(rem.Props, "milestone-status"))
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
	require.Len(t, meta.Parties, 1)
	assert.Equal(t, "security-team@example.com", meta.Parties[0].Name)
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
	require.Len(t, risk.RiskLog.Entries, 1)
	assert.Equal(t, "2027-03-15T12:00:00Z", risk.RiskLog.Entries[0].Start)
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

func TestConvertHDFToOSCALPOAM_RoundTrip(t *testing.T) {
	// Start with an HDF Amendments document
	amendments := hdf.HDFAmendments{
		Name: "round-trip-test",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.Poam,
				RequirementID: "AC-2 (3)",
				Reason:        "Account management controls pending deployment",
				Status:        resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{
					Type:       hdf.Simple,
					Identifier: "security-admin",
				},
				AppliedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
				Milestones: []hdf.Milestone{
					{
						Description:         "Deploy account management tool",
						EstimatedCompletion: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
						Status:              hdf.Pending,
					},
				},
			},
		},
	}

	// Convert HDF Amendments -> OSCAL POA&M
	input, err := json.Marshal(amendments)
	require.NoError(t, err)

	oscalOutput, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	// Convert OSCAL POA&M -> HDF Amendments (using the forward converter)
	hdfOutput, err := oscal.ConvertPOAMToHDF(oscalOutput, "1.0.0")
	require.NoError(t, err)

	// Verify structural consistency (not exact equality, since UUIDs change
	// and some fields get normalized)
	assert.Equal(t, "round-trip-test", hdfOutput.Name)
	require.Len(t, hdfOutput.Overrides, 1)

	override := hdfOutput.Overrides[0]
	// The requirement ID should survive the round trip.
	// Forward: "AC-2 (3)" -> OSCAL title "AC-2 (3)" -> risk prop "ac-2.3"
	// Reverse: risk prop "ac-2.3" -> ControlIDToNistTag -> "AC-2 (3)"
	assert.Equal(t, "AC-2 (3)", override.RequirementID)
	assert.Equal(t, "Account management controls pending deployment", override.Reason)
	require.NotNil(t, override.Status)
	assert.Equal(t, hdf.Failed, *override.Status)

	// Milestones should survive round trip
	require.Len(t, override.Milestones, 1)
	assert.Contains(t, override.Milestones[0].Description, "Deploy account management tool")
}
