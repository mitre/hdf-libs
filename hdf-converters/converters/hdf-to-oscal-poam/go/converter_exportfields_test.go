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

func strPtr(s string) *string   { return &s }
func f64Ptr(f float64) *float64 { return &f }

func convertToPOAM(t *testing.T, a hdf.HDFAmendments) *oscal.PlanOfActionAndMilestones {
	t.Helper()
	input, err := json.Marshal(a)
	require.NoError(t, err)
	out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)
	var doc oscal.OscalDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.NotNil(t, doc.PlanOfActionAndMilestones)
	return doc.PlanOfActionAndMilestones
}

func propVal(props []oscal.Property, name string) (string, bool) {
	for _, p := range props {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func facetVal(facets []oscal.Facet, name string) (string, bool) {
	for _, f := range facets {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

// TestExport_MetadataDeterminism pins that last-modified comes from the source
// appliedAt (not the wall clock), version is sourced, and description rides on
// remarks. Running twice must produce identical metadata.
func TestExport_MetadataDeterminism(t *testing.T) {
	appliedAt := time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC)
	amendments := hdf.HDFAmendments{
		Name:        "det-test",
		Version:     strPtr("7"),
		Description: strPtr("Imported advisory ADV-1"),
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "AC-1", Reason: "r",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
			AppliedAt: appliedAt,
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		}},
	}

	poam := convertToPOAM(t, amendments)
	assert.Equal(t, "2022-03-03T11:00:00Z", poam.Metadata.LastModified)
	assert.Equal(t, "7", poam.Metadata.Version)
	assert.Equal(t, "Imported advisory ADV-1", poam.Metadata.Remarks)

	poam2 := convertToPOAM(t, amendments)
	assert.Equal(t, poam.Metadata.LastModified, poam2.Metadata.LastModified, "last-modified must be deterministic")
}

// TestExport_LastModifiedLatestOverride pins that the newest override appliedAt
// wins for the document last-modified.
func TestExport_LastModifiedLatestOverride(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "multi-date",
		Overrides: []hdf.StandaloneOverride{
			{
				Type: hdf.Poam, RequirementID: "AC-1", Reason: "r1",
				Status:    resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
				AppliedAt: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
			{
				Type: hdf.Poam, RequirementID: "AC-2", Reason: "r2",
				Status:    resultStatusPtr(hdf.Failed),
				AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
				AppliedAt: time.Date(2023, 6, 15, 9, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	poam := convertToPOAM(t, amendments)
	assert.Equal(t, "2023-06-15T09:00:00Z", poam.Metadata.LastModified)
}

// TestExport_Cvss pins that override.cvss becomes a risk characterization whose
// facets carry the scores/vectors and whose origin actor attributes the applier.
func TestExport_Cvss(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "cvss-test",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.RiskAdjustment, RequirementID: "CVE-2021-44228", Reason: "adjusted",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "analyst"},
			AppliedAt: time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			Cvss: &hdf.Cvss{
				Version:      hdf.The31,
				BaseScore:    f64Ptr(9.8),
				BaseSeverity: (*hdf.CVSSSeverity)(strPtr(string(hdf.CVSSSeverityCritical))),
				BaseVector:   strPtr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			},
		}},
	}
	poam := convertToPOAM(t, amendments)
	require.Len(t, poam.Risks, 1)
	require.Len(t, poam.Risks[0].Characterizations, 1)
	ch := poam.Risks[0].Characterizations[0]

	require.NotNil(t, ch.Origin)
	require.Len(t, ch.Origin.Actors, 1)
	assert.Equal(t, "party", ch.Origin.Actors[0].Type)
	// Actor references the applier party.
	require.NotEmpty(t, poam.Metadata.Parties)
	assert.Equal(t, poam.Metadata.Parties[0].UUID, ch.Origin.Actors[0].ActorID)

	v, ok := facetVal(ch.Facets, "base_score")
	require.True(t, ok)
	assert.Equal(t, "9.8", v)
	v, _ = facetVal(ch.Facets, "base_severity")
	assert.Equal(t, "critical", v)
	v, _ = facetVal(ch.Facets, "base_vector")
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", v)
	for _, f := range ch.Facets {
		assert.Equal(t, "http://www.first.org/cvss/v3.1", f.System)
	}
}

// TestExport_Evidence pins that override.evidence becomes observations linked
// back from the poam-item.
func TestExport_Evidence(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "evidence-test",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "CVE-2021-44228", Reason: "r",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "vendor"},
			AppliedAt: time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			Evidence: []hdf.Evidence{{
				Type:        hdf.URL,
				Data:        "https://psirt.example.com/ADV-1",
				Description: strPtr("CSAF VEX advisory"),
			}},
		}},
	}
	poam := convertToPOAM(t, amendments)
	require.Len(t, poam.Observations, 1)
	obs := poam.Observations[0]
	assert.Equal(t, "CSAF VEX advisory", obs.Description)
	assert.Equal(t, []string{"EXAMINE"}, obs.Methods)
	assert.Equal(t, "2022-03-03T11:00:00Z", obs.Collected)
	require.Len(t, obs.RelevantEvidence, 1)
	assert.Equal(t, "https://psirt.example.com/ADV-1", obs.RelevantEvidence[0].Href)

	require.Len(t, poam.POAMItems, 1)
	require.Len(t, poam.POAMItems[0].RelatedObservations, 1)
	assert.Equal(t, obs.UUID, poam.POAMItems[0].RelatedObservations[0].ObservationUUID)
}

// TestExport_Justification pins justification onto a risk prop, mirroring
// override-type.
func TestExport_Justification(t *testing.T) {
	j := hdf.ComponentNotPresent
	amendments := hdf.HDFAmendments{
		Name: "just-test",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.FalsePositive, RequirementID: "CVE-2021-44228", Reason: "no java",
			Status:        resultStatusPtr(hdf.Passed),
			Justification: &j,
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "vendor"},
			AppliedAt:     time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		}},
	}
	poam := convertToPOAM(t, amendments)
	require.Len(t, poam.Risks, 1)
	v, ok := propVal(poam.Risks[0].Props, "justification")
	require.True(t, ok)
	assert.Equal(t, "component_not_present", v)
}

// TestExport_ExternalReferences pins external references onto back-matter
// resources.
func TestExport_ExternalReferences(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name: "ref-test",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "CVE-2021-44228", Reason: "r",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "vendor"},
			AppliedAt: time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			ExternalReferences: []hdf.ExternalReference{{
				SourceName:  "cve",
				ExternalID:  strPtr("CVE-2021-44228"),
				Href:        strPtr("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
				Description: strPtr("NVD entry"),
			}},
		}},
	}
	poam := convertToPOAM(t, amendments)
	require.NotNil(t, poam.BackMatter)
	require.Len(t, poam.BackMatter.Resources, 1)
	res := poam.BackMatter.Resources[0]
	assert.Equal(t, "cve", res.Title)
	assert.Equal(t, "NVD entry", res.Description)
	require.Len(t, res.Rlinks, 1)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", res.Rlinks[0].Href)
	v, ok := propVal(res.Props, "external-id")
	require.True(t, ok)
	assert.Equal(t, "CVE-2021-44228", v)
}

// TestExport_ApprovedBy pins the authorizing official onto a distinct
// responsible-party role — a mirror of the prepared-by path.
func TestExport_ApprovedBy(t *testing.T) {
	amendments := hdf.HDFAmendments{
		Name:       "approve-test",
		AppliedBy:  &hdf.Identity{Type: hdf.Simple, Identifier: "preparer"},
		ApprovedBy: &hdf.Identity{Type: hdf.Simple, Identifier: "official"},
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "AC-1", Reason: "r",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "preparer"},
			AppliedAt: time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		}},
	}
	poam := convertToPOAM(t, amendments)
	var approvedPartyID string
	for _, rp := range poam.Metadata.ResponsibleParties {
		if rp.RoleID == "approved-by" {
			require.Len(t, rp.PartyIDs, 1)
			approvedPartyID = rp.PartyIDs[0]
		}
	}
	require.NotEmpty(t, approvedPartyID, "approved-by responsible party must exist")
	var found bool
	for _, p := range poam.Metadata.Parties {
		if p.UUID == approvedPartyID {
			assert.Equal(t, "official", p.Name)
			found = true
		}
	}
	assert.True(t, found)
	// The role must be declared.
	var haveRole bool
	for _, r := range poam.Metadata.Roles {
		if r.ID == "approved-by" {
			haveRole = true
		}
	}
	assert.True(t, haveRole)
}

// TestExport_MinorProps pins the low-value prop homes (baseline/component ref,
// amendment id, labels) and milestone completion attribution.
func TestExport_MinorProps(t *testing.T) {
	completedAt := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	amendments := hdf.HDFAmendments{
		Name:        "minor-test",
		AmendmentID: strPtr("AMD-42"),
		Labels:      map[string]string{"zone": "prod", "env": "gov"},
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "AC-1", Reason: "r",
			Status:       resultStatusPtr(hdf.Failed),
			BaselineRef:  strPtr("nist-800-53r5"),
			ComponentRef: strPtr("comp-uuid-1"),
			AppliedBy:    hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
			AppliedAt:    time.Date(2022, 3, 3, 11, 0, 0, 0, time.UTC),
			ExpiresAt:    time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			Milestones: []hdf.Milestone{{
				Description:         "patch",
				EstimatedCompletion: time.Date(2099, 6, 30, 0, 0, 0, 0, time.UTC),
				Status:              hdf.Completed,
				CompletedAt:         &completedAt,
				CompletedBy:         &hdf.Identity{Type: hdf.Simple, Identifier: "ops"},
			}},
		}},
	}
	poam := convertToPOAM(t, amendments)

	// Labels emit in sorted key order.
	require.GreaterOrEqual(t, len(poam.Metadata.Props), 3)
	amdID, ok := propVal(poam.Metadata.Props, "amendment-id")
	require.True(t, ok)
	assert.Equal(t, "AMD-42", amdID)
	env, ok := propVal(poam.Metadata.Props, "env")
	require.True(t, ok)
	assert.Equal(t, "gov", env)

	risk := poam.Risks[0]
	v, ok := propVal(risk.Props, "baseline-ref")
	require.True(t, ok)
	assert.Equal(t, "nist-800-53r5", v)
	v, ok = propVal(risk.Props, "component-ref")
	require.True(t, ok)
	assert.Equal(t, "comp-uuid-1", v)

	require.Len(t, risk.Remediations, 1)
	require.Len(t, risk.Remediations[0].Tasks, 1)
	cb, ok := propVal(risk.Remediations[0].Tasks[0].Props, "completed-by")
	require.True(t, ok)
	assert.Equal(t, "ops", cb)
	ca, ok := propVal(risk.Remediations[0].Tasks[0].Props, "completed-at")
	require.True(t, ok)
	assert.Equal(t, "2023-01-01T00:00:00Z", ca)
}

// TestExport_RoundTripAppliedAtVersion strengthens the round trip: appliedAt and
// version now survive HDF → OSCAL → HDF.
func TestExport_RoundTripAppliedAtVersion(t *testing.T) {
	appliedAt := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	amendments := hdf.HDFAmendments{
		Name:    "rt-test",
		Version: strPtr("3.2"),
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "AC-1", Reason: "r",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
			AppliedAt: appliedAt,
			ExpiresAt: time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
		}},
	}
	input, err := json.Marshal(amendments)
	require.NoError(t, err)
	oscalOut, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)
	hdfOut, err := oscal.ConvertPOAMToHDF(oscalOut, "1.0.0")
	require.NoError(t, err)

	require.NotNil(t, hdfOut.Version)
	assert.Equal(t, "3.2", *hdfOut.Version)
	require.Len(t, hdfOut.Overrides, 1)
	assert.True(t, appliedAt.Equal(hdfOut.Overrides[0].AppliedAt), "appliedAt should round-trip")
}
