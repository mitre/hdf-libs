package hdftocyclonedxvex

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCycloneDXVEX_OutputCountAnchor is the export-side ground-truth
// anchor. hdf-to-cyclonedx-vex drops non-CVE overrides and emits one vulnerability
// per distinct CVE-shaped requirementId. So the emitted vulnerabilities count
// must equal the distinct-CVE count derived independently from the HDF Amendments
// input (not the converter's parser). The MultiCVE fixture has 3 distinct CVEs.
func TestConvertHDFToCycloneDXVEX_OutputCountAnchor(t *testing.T) {
	input := fixtures.Amendments.MultiCVE
	want := shared.CountDistinctCVEOverrides(t, input)
	require.Greater(t, want, 1, "fixture must have multiple distinct CVEs for a meaningful anchor")

	out, err := ConvertHDFToCycloneDXVEX(input, "1.0.0")
	require.NoError(t, err)

	got := shared.CountJSONItemsUnderKey(t, out, "vulnerabilities")
	require.Equal(t, want, got, "one CycloneDX vulnerability per distinct CVE-shaped override")
}
