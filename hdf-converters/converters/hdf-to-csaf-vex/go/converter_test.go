package hdftocsafvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	csafvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/csaf-vex-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tm
}

const testVersion = "test"

func loadInput(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func TestConvertHDFToCSAFVEX_KnownNotAffectedExport(t *testing.T) {
	t.Parallel()
	out, err := ConvertHDFToCSAFVEX(loadInput(t, "sec-vex-amendments.json"), testVersion)
	require.NoError(t, err)

	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))

	assert.Equal(t, "csaf_vex", doc.Document.Category)
	assert.Equal(t, "2.0", doc.Document.CSAFVersion)
	require.Len(t, doc.Vulnerabilities, 3, "three CVEs from the secvisogram fixture")

	for _, v := range doc.Vulnerabilities {
		require.NotNil(t, v.ProductStatus)
		assert.NotEmpty(t, v.ProductStatus.KnownNotAffected, "all three should land in known_not_affected")
		require.Len(t, v.Flags, 1, "each should carry the justification flag round-tripped")
		assert.Equal(t, "component_not_present", v.Flags[0].Label)
	}
}

func TestConvertHDFToCSAFVEX_FixedExportProducesOpenPoamAsAffected(t *testing.T) {
	t.Parallel()
	// uc-01-fixed-amendments.json was imported as a POA&M pinned to 'failed'
	// with a pending milestone. Without closure, the export must treat the
	// POA&M as still-affected (not 'fixed') — supplier-claim vs real-system.
	out, err := ConvertHDFToCSAFVEX(loadInput(t, "uc-01-fixed-amendments.json"), testVersion)
	require.NoError(t, err)

	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1)
	v := doc.Vulnerabilities[0]
	require.NotNil(t, v.ProductStatus)
	assert.Empty(t, v.ProductStatus.Fixed,
		"open POA&M (milestone pending) must NOT emit as 'fixed' on export")
	assert.NotEmpty(t, v.ProductStatus.KnownAffected,
		"open POA&M from VEX 'fixed' is still 'known_affected' to the assessed system")
	assert.NotEmpty(t, v.Remediations, "milestone description surfaces as a remediation")
}

func TestConvertHDFToCSAFVEX_RoundTripPreservesCanonicalFields(t *testing.T) {
	t.Parallel()
	// Round-trip: CSAF VEX -> HDF Amendments -> CSAF VEX. The CVE id,
	// status bucket (known_not_affected), and justification flag are the
	// canonical consumer-action payload — they MUST survive untouched.
	csafInput, err := os.ReadFile(filepath.Join("..", "..", "csaf-vex-to-hdf",
		"fixtures", "input", "sec-vex-2022-0001.json"))
	require.NoError(t, err)

	amendments, err := csafvex.ConvertCSAFVEXToHDF(csafInput, testVersion)
	require.NoError(t, err)
	hdfBytes, err := json.Marshal(amendments)
	require.NoError(t, err)

	csafOutput, err := ConvertHDFToCSAFVEX(hdfBytes, testVersion)
	require.NoError(t, err)

	var roundTripped CSAFVexDocument
	require.NoError(t, json.Unmarshal(csafOutput, &roundTripped))

	originalCVEs := []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}
	require.Len(t, roundTripped.Vulnerabilities, len(originalCVEs))
	for i, v := range roundTripped.Vulnerabilities {
		assert.Equal(t, originalCVEs[i], v.CVE)
		require.NotNil(t, v.ProductStatus)
		assert.NotEmpty(t, v.ProductStatus.KnownNotAffected,
			"not_affected status must survive round-trip")
		require.Len(t, v.Flags, 1, "justification flag must survive round-trip")
		assert.Equal(t, "component_not_present", v.Flags[0].Label)
	}
}

func TestConvertHDFToCSAFVEX_NonCVEOverridesAreSkipped(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "Mixed amendments",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.FalsePositive,
				RequirementID: "AC-2", // non-CVE; must be skipped
				Status:        &passed,
				AppliedAt:     now,
				ExpiresAt:     exp,
				AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "alice"},
				Reason:        "compensating control",
			},
			{
				Type:          hdf.FalsePositive,
				RequirementID: "CVE-2024-99999",
				Status:        &passed,
				AppliedAt:     now,
				ExpiresAt:     exp,
				AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "alice"},
				Reason:        "not affected",
			},
		},
	}
	body, err := json.Marshal(amendments)
	require.NoError(t, err)

	out, err := ConvertHDFToCSAFVEX(body, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1, "only the CVE-shaped requirementId survives")
	assert.Equal(t, "CVE-2024-99999", doc.Vulnerabilities[0].CVE)
}

func TestConvertHDFToCSAFVEX_ErrorsOnNoCVEOverrides(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "No CVE amendments",
		Overrides: []hdf.StandaloneOverride{{
			Type:          hdf.Attestation,
			RequirementID: "AC-1",
			Status:        &passed,
			AppliedAt:     now,
			ExpiresAt:     exp,
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "x"},
			Reason:        "manual review",
		}},
	}
	body, err := json.Marshal(amendments)
	require.NoError(t, err)
	_, err = ConvertHDFToCSAFVEX(body, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no overrides with CVE-shaped requirementIds")
}

func TestConvertHDFToCSAFVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToCSAFVEX([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertHDFToCSAFVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToCSAFVEX(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestProductIDsFor_PrefersComponentRef(t *testing.T) {
	t.Parallel()
	ref := "MY-COMPONENT-UUID"
	o := &hdf.StandaloneOverride{ComponentRef: &ref, Reason: "Products: IGNORED"}
	assert.Equal(t, []string{"MY-COMPONENT-UUID"}, productIDsFor(o))
}

func TestProductIDsFor_ParsesReasonLine(t *testing.T) {
	t.Parallel()
	o := &hdf.StandaloneOverride{Reason: "lots of prose\nProducts: CSAFPID-1, CSAFPID-2"}
	assert.Equal(t, []string{"CSAFPID-1", "CSAFPID-2"}, productIDsFor(o))
}

func TestProductIDsFor_FallsBackToDefault(t *testing.T) {
	t.Parallel()
	o := &hdf.StandaloneOverride{Reason: "no products line here"}
	assert.Equal(t, []string{defaultProductID}, productIDsFor(o))
}

func TestStripProductsLineRemovesTail(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "prose", stripProductsLine("prose\nProducts: A, B"))
	assert.Equal(t, "only prose", stripProductsLine("only prose"))
}
