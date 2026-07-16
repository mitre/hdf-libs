package hdftosplunk

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToSplunk_OutputCountAnchor is the export-side ground-truth anchor:
// hdf-to-splunk emits one NDJSON HEC event per HDF requirement, so the emitted
// record count must equal the requirement count derived independently from the
// HDF input (sum of baselines[].requirements — not the converter's parser).
func TestConvertHDFToSplunk_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered
	want := shared.CountHDFResultRequirements(t, input)
	require.Greater(t, want, 1, "fixture must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToSplunk(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountNDJSONRecords(t, out)
	require.Equal(t, want, got, "one Splunk HEC event per HDF requirement")
}
