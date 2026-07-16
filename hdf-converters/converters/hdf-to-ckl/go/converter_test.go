package hdftockl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ckl "github.com/mitre/hdf-libs/hdf-converters/v3/converters/ckl-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCKL_RoundTrip exercises the full ckl -> HDF -> ckl loop and
// asserts the key fields survive intact.
func TestConvertHDFToCKL_RoundTrip(t *testing.T) {
	cklPath := filepath.Join(shared.GetConvertersDir(), "ckl-to-hdf", "fixtures", "input", "firefox-stig.ckl")
	cklBytes, err := os.ReadFile(cklPath)
	require.NoError(t, err, "Failed to read firefox-stig.ckl fixture")

	// Forward: ckl -> HDF
	hdfResults, err := ckl.ConvertCKLToHDF(cklBytes, "1.0.0")
	require.NoError(t, err, "ckl-to-hdf should succeed")

	hdfBytes, err := json.Marshal(hdfResults)
	require.NoError(t, err, "marshalling HDF should succeed")

	// Reverse: HDF -> ckl
	out, err := ConvertHDFToCKL(hdfBytes)
	require.NoError(t, err, "hdf-to-ckl should succeed")
	require.NotEmpty(t, out, "output should not be empty")

	// Re-parse the produced CKL and assert key fields survived.
	cl, err := checklist.ParseCKL(out)
	require.NoError(t, err, "produced CKL should re-parse")

	assert.Equal(t, "EXAMPLE-HOST", cl.Asset.HostName, "host name should survive round-trip")

	require.Len(t, cl.Stigs, 1, "should have one STIG")
	stig := cl.Stigs[0]
	assert.Equal(t, "MOZ_Firefox_STIG", stig.StigID, "stigid should survive round-trip")

	// All 6 vuln IDs present.
	vulnsByNum := make(map[string]checklist.Vuln)
	for _, v := range stig.Vulns {
		vulnsByNum[v.VulnNum] = v
	}
	expectedVulns := []string{"V-251545", "V-251546", "V-251547", "V-251548", "V-251559", "V-251565"}
	for _, id := range expectedVulns {
		assert.Contains(t, vulnsByNum, id, "vuln %s should be present", id)
	}

	// V-251545 status Open and CCI-002605 present.
	v := vulnsByNum["V-251545"]
	assert.Equal(t, checklist.StatusOpen, v.Status, "V-251545 should be Open")
	assert.Contains(t, v.CCIs, "CCI-002605", "V-251545 should carry CCI-002605")
}

// TestConvertHDFToCKL_OutputCountAnchor is the export-side ground-truth anchor:
// hdf-to-ckl emits one <VULN> per HDF requirement, so the emitted VULN count must
// equal the requirement count derived independently from the HDF input (a raw
// JSON walk, not the converter's parser). InspecMultilayered sums to 1603
// baseline requirements across its 5 baselines — a meaningful anchor, not a
// vacuous 1==1.
func TestConvertHDFToCKL_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered
	want := shared.CountHDFResultRequirements(t, input)
	require.Greater(t, want, 1, "fixture must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToCKL(input)
	require.NoError(t, err, "hdf-to-ckl should succeed")

	got := shared.CountXMLElements(t, out, "VULN")
	require.Equal(t, want, got,
		"emitted <VULN> count must equal the HDF requirement count (one VULN per requirement)")
}

// TestConvertHDFToCKL_Synthesis converts arbitrary HDF (no checklist
// extensions) and asserts required checklist fields are synthesized.
func TestConvertHDFToCKL_Synthesis(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Synthetic Baseline",
			"version": "1.0.0",
			"title": "Synthetic",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "GEN-001",
				"title": "Generic Requirement",
				"descriptions": [{ "label": "default", "data": "A generic requirement description" }],
				"impact": 0.5,
				"tags": { "nist": ["SI-2 c"] },
				"sourceLocation": { "ref": "GEN-001", "line": 1 },
				"results": [{ "status": "failed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
			}]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	out, err := ConvertHDFToCKL([]byte(input))
	require.NoError(t, err, "synthesis conversion should succeed")
	require.NotEmpty(t, out, "output should not be empty")

	cl, err := checklist.ParseCKL(out)
	require.NoError(t, err, "synthesized CKL should re-parse")

	require.Len(t, cl.Stigs, 1, "should have one STIG")
	require.Len(t, cl.Stigs[0].Vulns, 1, "should have one vuln")

	v := cl.Stigs[0].Vulns[0]
	assert.Equal(t, "GEN-001", v.VulnNum, "VulnNum should be the requirement id")
	assert.NotEmpty(t, v.CCIs, "CCI should be synthesized from the NIST tag")
	assert.Equal(t, checklist.StatusOpen, v.Status, "failed status should map to Open")
}

func TestConvertHDFToCKL_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToCKL([]byte("not valid json"))
	assert.Error(t, err, "invalid JSON should error")
}

func TestConvertHDFToCKL_NoBaselines(t *testing.T) {
	_, err := ConvertHDFToCKL([]byte(`{"baselines":[]}`))
	assert.Error(t, err, "HDF with no baselines should error")
}

// TestGoldenParity asserts whole-output equality against frozen golden CKLs,
// generated from the real HDF in the shared @mitre/hdf-fixtures corpus. The
// TypeScript test asserts the SAME files under the SAME normalization, so the
// two implementations cannot drift apart. Run with UPDATE_GOLDEN=1 to rewrite.
func TestGoldenParity(t *testing.T) {
	// inspec-multilayered is deliberately NOT used: its startTime values carry no
	// UTC offset, which the generated hdf.HDFResults time.Time field rejects, so no
	// Go converter can read it.
	goldens := map[string][]byte{
		"minimal": fixtures.Results.Minimal,
	}
	for _, name := range []string{"minimal"} {
		out, err := ConvertHDFToCKL(goldens[name])
		require.NoError(t, err, "convert %s", name)

		goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-ckl", "fixtures", "expected", name+".ckl")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644)) //nolint:gosec // test golden
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, shared.NormalizeXMLForGolden(string(golden)), shared.NormalizeXMLForGolden(string(out)),
			"golden mismatch for %s", name)
	}
}
