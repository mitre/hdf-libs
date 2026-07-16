package hdftooscalpoam

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToOSCALPOAM_OutputCountAnchor is the export-side ground-truth
// anchor: hdf-to-oscal-poam emits one poam-item per HDF override, so the emitted
// poam-item count must equal the override count derived independently from the
// HDF Amendments input (top-level overrides[], a raw JSON walk — not the
// converter's parser). The MultiCVE fixture has 3 overrides.
func TestConvertHDFToOSCALPOAM_OutputCountAnchor(t *testing.T) {
	input := fixtures.Amendments.MultiCVE
	want := shared.CountHDFOverrides(t, input)
	require.Greater(t, want, 1, "fixture must have multiple overrides for a meaningful anchor")

	out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountJSONItemsUnderKey(t, out, "poam-items")
	require.Equal(t, want, got, "one OSCAL poam-item per HDF override")
}
