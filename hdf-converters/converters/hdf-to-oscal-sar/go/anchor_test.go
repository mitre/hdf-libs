package hdftooscalsar

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToOSCALSAR_OutputCountAnchor is the export-side ground-truth
// anchor: hdf-to-oscal-sar emits one OSCAL finding per HDF requirement (across
// one OSCAL result per baseline), so the total findings count must equal the
// requirement count derived independently from the HDF input (sum of
// baselines[].requirements — not the converter's parser). CountJSONItemsUnderKey
// sums every results[].findings[] array, matching that total.
func TestConvertHDFToOSCALSAR_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered
	want := shared.CountHDFResultRequirements(t, input)
	require.Greater(t, want, 1, "fixture must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountJSONItemsUnderKey(t, out, "findings")
	require.Equal(t, want, got, "one OSCAL finding per HDF requirement")
}
