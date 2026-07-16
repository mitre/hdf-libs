package hdftoopenvex

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToOpenVEX_OutputCountAnchor is the export-side ground-truth
// anchor. hdf-to-openvex drops non-CVE overrides and emits one statement per
// CVE-shaped requirementId per status bucket. When each CVE resolves to a single
// status bucket, the statement count equals the distinct-CVE count derived
// independently from the HDF Amendments input (not the converter's parser). The
// MultiCVE fixture has 3 distinct CVEs, all falsePositive (a single bucket each)
// → 3 statements.
func TestConvertHDFToOpenVEX_OutputCountAnchor(t *testing.T) {
	input := fixtures.Amendments.MultiCVE
	want := shared.CountDistinctCVEOverrides(t, input)
	require.Greater(t, want, 1, "fixture must have multiple distinct CVEs for a meaningful anchor")

	out, err := ConvertHDFToOpenVEX(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountJSONItemsUnderKey(t, out, "statements")
	require.Equal(t, want, got, "one OpenVEX statement per distinct CVE-shaped override (single status bucket each)")
}
