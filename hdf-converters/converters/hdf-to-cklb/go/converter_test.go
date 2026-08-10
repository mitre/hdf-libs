package hdftocklb

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

// TestConvertHDFToCKLB_OverrideAndEffectiveStatus pins the export-fidelity fixes
// end-to-end: effectiveStatus drives status, a risk-adjustment override surfaces
// into overrides.severity + comments, and finding_details composes all results.
func TestConvertHDFToCKLB_OverrideAndEffectiveStatus(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "b", "version": "1.0.0", "title": "T", "maintainer": "M",
			"supports": [], "inputs": [], "groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "V-1", "title": "Rule",
				"descriptions": [{ "label": "default", "data": "d" }],
				"impact": 0.7,
				"effectiveStatus": "notApplicable",
				"tags": { "nist": ["SI-2 c"] },
				"statusOverrides": [{
					"type": "riskAdjustment", "reason": "compensating control",
					"appliedBy": { "type": "username", "identifier": "jdoe" },
					"appliedAt": "2020-01-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
					"impact": { "value": 0.4 }
				}],
				"results": [
					{ "status": "passed", "codeDesc": "port 22 closed", "startTime": "2026-01-29T18:00:00Z" },
					{ "status": "failed", "codeDesc": "port 23 closed", "message": "telnet open", "startTime": "2026-01-29T18:00:00Z" }
				]
			}]
		}],
		"components": [], "statistics": { "duration": 0 }
	}`

	out, err := ConvertHDFToCKLB([]byte(input))
	require.NoError(t, err)
	s := string(out)

	assert.Contains(t, s, `"status": "not_applicable"`, "effectiveStatus drives status")
	assert.Contains(t, s, `"severity": "medium"`, "impact 0.4 -> medium override")
	assert.Contains(t, s, `"justification": "compensating control"`)
	assert.Contains(t, s, "Override [riskAdjustment]: compensating control")
	assert.Contains(t, s, `[passed] port 22 closed`)
	assert.Contains(t, s, `[failed] port 23 closed`)
	assert.Contains(t, s, `telnet open`)

	// Re-parse to confirm the override object round-trips through the model.
	cl, err := checklist.ParseCKLB(out)
	require.NoError(t, err)
	v := findVuln(t, cl, "V-1")
	assert.Equal(t, "medium", v.SeverityOverride)
}

func TestConvertHDFToCKLB_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToCKLB([]byte("not valid json"))
	assert.Error(t, err)
}

func TestConvertHDFToCKLB_NoBaselines(t *testing.T) {
	_, err := ConvertHDFToCKLB([]byte(`{"baselines":[]}`))
	assert.Error(t, err)
}

// TestGoldenParity asserts byte-for-byte output against frozen golden CKLBs,
// generated from the real HDF in the shared @mitre/hdf-fixtures corpus. The
// TypeScript test asserts the SAME files, so the two implementations cannot
// drift apart. Run with UPDATE_GOLDEN=1 to rewrite.
func TestGoldenParity(t *testing.T) {
	// inspec-multilayered is deliberately NOT used: its startTime values carry no
	// UTC offset, which the generated hdf.HDFResults time.Time field rejects, so no
	// Go converter can read it.
	goldens := map[string][]byte{
		"minimal": fixtures.Results.Minimal,
	}
	for _, name := range []string{"minimal"} {
		out, err := ConvertHDFToCKLB(goldens[name])
		require.NoError(t, err, "convert %s", name)

		goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-cklb", "fixtures", "expected", name+".cklb")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644)) //nolint:gosec // test golden
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, string(golden), string(out), "golden mismatch for %s", name)
	}
}
