package hdftocklb

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCKLB_OutputCountAnchor is the export-side ground-truth anchor:
// hdf-to-cklb emits one rule per HDF requirement, so the emitted rule count must
// equal the requirement count derived independently from the HDF input (sum of
// baselines[].requirements, a raw JSON walk — not the converter's parser).
func TestConvertHDFToCKLB_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered
	want := shared.CountHDFResultRequirements(t, input)
	require.Greater(t, want, 1, "fixture must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToCKLB(input)
	require.NoError(t, err)

	got := shared.CountJSONItemsUnderKey(t, out, "rules")
	require.Equal(t, want, got, "one cklb rule per HDF requirement")
}
