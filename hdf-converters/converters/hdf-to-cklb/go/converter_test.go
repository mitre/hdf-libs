package hdftocklb

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

// findVuln returns the vuln with the given Vuln_Num across all stigs.
func findVuln(t *testing.T, cl *checklist.Checklist, vulnNum string) *checklist.Vuln {
	t.Helper()
	for i := range cl.Stigs {
		for j := range cl.Stigs[i].Vulns {
			if cl.Stigs[i].Vulns[j].VulnNum == vulnNum {
				return &cl.Stigs[i].Vulns[j]
			}
		}
	}
	t.Fatalf("vuln %s not found", vulnNum)
	return nil
}

func countVulns(cl *checklist.Checklist) int {
	n := 0
	for i := range cl.Stigs {
		n += len(cl.Stigs[i].Vulns)
	}
	return n
}

// TestConvertHDFToCKLB_RoundTrip exercises the full CKL -> HDF -> CKLB path
// using the committed firefox-stig.ckl fixture, asserting the passthrough is
// preserved and the output carries CKLB (snake_case JSON) shape.
func TestConvertHDFToCKLB_RoundTrip(t *testing.T) {
	cklPath := filepath.Join(shared.GetConvertersDir(), "ckl-to-hdf", "fixtures", "input", "firefox-stig.ckl")
	cklBytes, err := os.ReadFile(cklPath)
	require.NoError(t, err, "read firefox-stig.ckl fixture")

	results, err := ckl.ConvertCKLToHDF(cklBytes, "1.0.0")
	require.NoError(t, err, "ckl-to-hdf forward conversion")

	hdfBytes, err := json.Marshal(results)
	require.NoError(t, err, "marshal HDF results")

	out, err := ConvertHDFToCKLB(hdfBytes)
	require.NoError(t, err, "hdf-to-cklb conversion")
	require.NotEmpty(t, out)

	// Re-parse the CKLB output and assert semantic content.
	cl, err := checklist.ParseCKLB(out)
	require.NoError(t, err, "re-parse CKLB output")

	assert.Equal(t, 6, countVulns(cl), "firefox STIG has 6 vulns")
	assert.Equal(t, "EXAMPLE-HOST", cl.Asset.HostName)

	v := findVuln(t, cl, "V-251545")
	assert.Equal(t, checklist.StatusOpen, v.Status, "V-251545 is Open (canonical)")
	assert.Contains(t, v.CCIs, "CCI-002605")

	// Assert CKLB shape (snake_case JSON, NOT CKL XML attributes).
	outStr := string(out)
	assert.Contains(t, outStr, `"status": "open"`, "CKLB uses snake_case open status")
	assert.Contains(t, outStr, `"ccis"`, "CKLB uses a ccis array")
}

// TestConvertHDFToCKLB_Synthesis converts arbitrary HDF (no checklist
// passthrough extensions) and asserts the required checklist fields are
// synthesized into a valid CKLB.
func TestConvertHDFToCKLB_Synthesis(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Synth Baseline",
			"version": "1.0.0",
			"title": "Synthesized",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "GEN-001",
				"title": "Generic Requirement",
				"descriptions": [{ "label": "default", "data": "A generic check" }],
				"impact": 0.5,
				"tags": { "nist": ["SI-2 c"] },
				"sourceLocation": { "ref": "GEN-001", "line": 1 },
				"results": [{ "status": "failed", "codeDesc": "Check", "startTime": "2026-01-29T18:00:00.000Z" }]
			}]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	out, err := ConvertHDFToCKLB([]byte(input))
	require.NoError(t, err, "synthesis conversion")
	require.NotEmpty(t, out)

	cl, err := checklist.ParseCKLB(out)
	require.NoError(t, err, "re-parse synthesized CKLB")

	v := findVuln(t, cl, "GEN-001")
	assert.NotEmpty(t, v.CCIs, "synthesized vuln should have CCIs reverse-mapped from NIST")
	assert.Equal(t, checklist.StatusOpen, v.Status, "failed status maps to Open")
}

func TestConvertHDFToCKLB_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToCKLB([]byte("not valid json"))
	assert.Error(t, err)
}

func TestConvertHDFToCKLB_NoBaselines(t *testing.T) {
	_, err := ConvertHDFToCKLB([]byte(`{"baselines":[]}`))
	assert.Error(t, err)
}
