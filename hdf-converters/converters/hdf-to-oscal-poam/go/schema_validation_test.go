package hdftooscalpoam

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToOSCALPOAM_SchemaValid gates the converter output on the NIST
// OSCAL v1.1.2 POA&M schema. The converter self-declares "oscal-version":
// "1.1.2", so its output must validate against exactly that schema. See
// ../schemas/PROVENANCE.md.
func TestConvertHDFToOSCALPOAM_SchemaValid(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))

	appliedAt := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	sysRef := "https://example.com/ssp.json"

	cases := []struct {
		label      string
		amendments hdf.HDFAmendments
	}{
		{
			label: "minimal poam override",
			amendments: hdf.HDFAmendments{
				Name: "test-poam",
				Overrides: []hdf.StandaloneOverride{
					{
						Type: hdf.Poam, RequirementID: "AC-1", Reason: "Pending remediation",
						Status:    resultStatusPtr(hdf.Failed),
						AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin@example.com"},
						AppliedAt: appliedAt, ExpiresAt: expiresAt,
					},
				},
			},
		},
		{
			label: "with system ref and multiple overrides",
			amendments: hdf.HDFAmendments{
				Name: "multi", SystemRef: &sysRef,
				Overrides: []hdf.StandaloneOverride{
					{
						Type: hdf.Poam, RequirementID: "AC-1", Reason: "r1",
						Status:    resultStatusPtr(hdf.Failed),
						AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "a@example.com"},
						AppliedAt: appliedAt, ExpiresAt: expiresAt,
					},
					{
						Type: hdf.Poam, RequirementID: "AC-2", Reason: "r2",
						Status:    resultStatusPtr(hdf.Failed),
						AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "b@example.com"},
						AppliedAt: appliedAt, ExpiresAt: expiresAt,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			input, err := json.Marshal(tc.amendments)
			require.NoError(t, err)
			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, tc.label, out)
		})
	}
}
