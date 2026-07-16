package hdftocsv

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCSV_OutputCountAnchor is the export-side ground-truth anchor.
// hdf-to-csv FANS OUT: it emits one data row per (requirement × target), where
// targets are the document's components (or a single empty target when there are
// none). So the data-row count must equal requirements × max(components, 1),
// derived independently from the HDF input (not the converter's parser). The
// InspecMultilayered fixture carries no components, so the factor is 1 and the
// row count equals the requirement count — but the anchor asserts the general
// fan-out relationship so a components fixture would still be covered.
func TestConvertHDFToCSV_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered
	reqs := shared.CountHDFResultRequirements(t, input)
	require.Greater(t, reqs, 1, "fixture must have multiple requirements for a meaningful anchor")

	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	require.NoError(t, json.Unmarshal(input, &doc))
	targets := len(doc.Components)
	if targets == 0 {
		targets = 1
	}
	want := reqs * targets

	out, err := ConvertHDFToCSV(input)
	require.NoError(t, err)

	// Parse as CSV so newlines inside quoted fields are not miscounted as rows.
	records, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	require.NoError(t, err, "output should be valid CSV")
	require.NotEmpty(t, records, "CSV should have at least a header row")
	got := len(records) - 1 // minus the header row

	require.Equal(t, want, got, "one CSV data row per (requirement × target)")
}
