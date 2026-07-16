package hdftocsafvex

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCSAFVEX_OutputCountAnchor is the export-side ground-truth
// anchor. hdf-to-csaf-vex drops non-CVE overrides and GROUPS by CVE, emitting one
// vulnerability per distinct CVE-shaped requirementId. So the emitted
// vulnerabilities count must equal the distinct-CVE count derived independently
// from the HDF Amendments input (not the converter's parser). The MultiCVE
// fixture has 3 distinct CVEs across its 3 overrides.
func TestConvertHDFToCSAFVEX_OutputCountAnchor(t *testing.T) {
	input := fixtures.Amendments.MultiCVE
	want := shared.CountDistinctCVEOverrides(t, input)
	require.Greater(t, want, 1, "fixture must have multiple distinct CVEs for a meaningful anchor")

	out, err := ConvertHDFToCSAFVEX(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountJSONItemsUnderKey(t, out, "vulnerabilities")
	require.Equal(t, want, got, "one CSAF vulnerability per distinct CVE-shaped override")
}
