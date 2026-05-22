package hdftockl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ckl "github.com/mitre/hdf-libs/hdf-converters/v3/converters/ckl-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
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
