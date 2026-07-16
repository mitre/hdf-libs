package hdftoxccdf

import (
	"encoding/json"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToXCCDF_OutputCountAnchor is the export-side ground-truth anchor.
// XCCDF is a SINGLE-benchmark format: hdf-to-xccdf emits one benchmark from
// baselines[0] only, with one <rule-result> per requirement in that baseline.
// So the emitted <rule-result> count must equal the FIRST baseline's requirement
// count — derived independently from the HDF input (not the converter's parser).
// (This deliberately differs from the whole-document requirement total; the
// single-benchmark collapse is the documented non-1:1 relationship.)
func TestConvertHDFToXCCDF_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered

	var doc struct {
		Baselines []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(input, &doc))
	require.NotEmpty(t, doc.Baselines, "fixture must have at least one baseline")
	want := len(doc.Baselines[0].Requirements)
	require.Greater(t, want, 1, "first baseline must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToXCCDF(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountXMLElements(t, out, "rule-result")
	require.Equal(t, want, got, "one <rule-result> per requirement in the first (only exported) baseline")
}
