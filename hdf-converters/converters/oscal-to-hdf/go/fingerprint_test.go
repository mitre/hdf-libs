package oscal

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOscalFingerprints(t *testing.T) {
	// Test all 7 OSCAL fingerprints
	tests := []struct {
		id         string
		label      string
		key        string
		outputType registry.OutputType
	}{
		{"oscal-ssp-to-hdf", "OSCAL SSP", "system-security-plan", registry.OutputRaw},
		{"oscal-sap-to-hdf", "OSCAL SAP", "assessment-plan", registry.OutputPlan},
		{"oscal-sar-to-hdf", "OSCAL SAR", "assessment-results", registry.OutputResults},
		{"oscal-poam-to-hdf", "OSCAL POA&M", "plan-of-action-and-milestones", registry.OutputAmendments},
		{"oscal-profile-to-hdf", "OSCAL Profile", "profile", registry.OutputBaseline},
		{"oscal-catalog-to-hdf", "OSCAL Catalog", "catalog", registry.OutputBaseline},
		{"oscal-component-to-hdf", "OSCAL Component", "component-definition", registry.OutputBaseline},
	}

	for _, tc := range tests {
		tc := tc // capture loop variable
		t.Run(tc.id+" is registered with correct metadata", func(t *testing.T) {
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp, "%s should be registered via init()", tc.id)
			assert.Equal(t, tc.label, fp.Label)
			assert.Equal(t, registry.DirectionIngest, fp.Direction)
			assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
			assert.Equal(t, tc.outputType, fp.OutputType)
		})

		t.Run(tc.id+" detects known-good input at confidence 1.0", func(t *testing.T) {
			input := map[string]any{
				tc.key: map[string]any{
					"uuid": "12345678-1234-1234-1234-123456789012",
				},
			}
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp)
			assert.Equal(t, 1.0, fp.Fingerprint(input))
		})

		t.Run(tc.id+" does not match different OSCAL type", func(t *testing.T) {
			// Use a key that is NOT this converter's key
			otherKey := "some-other-oscal-type"
			if tc.key == "system-security-plan" {
				otherKey = "catalog"
			}
			input := map[string]any{
				otherKey: map[string]any{
					"uuid": "12345678-1234-1234-1234-123456789012",
				},
			}
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp)
			assert.Equal(t, 0.0, fp.Fingerprint(input))
		})

		t.Run(tc.id+" does not match nil input", func(t *testing.T) {
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp)
			assert.Equal(t, 0.0, fp.Fingerprint(nil))
		})

		t.Run(tc.id+" does not match string input", func(t *testing.T) {
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp)
			assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
		})

		t.Run(tc.id+" detects oscal-version from metadata", func(t *testing.T) {
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp)
			require.NotNil(t, fp.DetectVersion, "OSCAL fingerprints should have DetectVersion")

			input := map[string]any{
				tc.key: map[string]any{
					"uuid": "test-uuid",
					"metadata": map[string]any{
						"oscal-version": "1.0.4",
						"title":         "Test",
					},
				},
			}
			assert.Equal(t, "1.0.4", fp.DetectVersion(input))
		})

		t.Run(tc.id+" returns empty version when metadata missing", func(t *testing.T) {
			fp := registry.GetFingerprint(tc.id)
			require.NotNil(t, fp)

			input := map[string]any{
				tc.key: map[string]any{
					"uuid": "test-uuid",
				},
			}
			assert.Equal(t, "", fp.DetectVersion(input))
		})
	}
}
