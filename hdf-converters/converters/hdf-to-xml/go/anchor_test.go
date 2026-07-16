package hdftoxml

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToXML_OutputCountAnchor is the export-side ground-truth anchor:
// hdf-to-xml faithfully serializes the HDF tree, emitting one <requirement>
// element per HDF requirement, so their count must equal the requirement count
// derived independently from the HDF input (sum of baselines[].requirements —
// not the converter's parser). The plural <requirements> wrappers (one per
// baseline) are a distinct local name and are not matched.
func TestConvertHDFToXML_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered
	want := shared.CountHDFResultRequirements(t, input)
	require.Greater(t, want, 1, "fixture must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToXML(input)
	require.NoError(t, err)

	got := shared.CountXMLElements(t, out, "requirement")
	require.Equal(t, want, got, "one <requirement> element per HDF requirement")
}
