package evals

import (
	"os"
	"path/filepath"
	"testing"
)

// Real fixture sources elsewhere in the repo (paths relative to this package,
// hdf-cli/internal/mcp/evals). The evals reuse these real fixtures by staging a
// copy into a temp HDF_MCP_ROOT — no committed duplicates, and nothing
// fabricated (repo Fixture Integrity rule).
const (
	fxSystem   = "../../../cmd/hdf/cmd/testdata/evidence-verify/system.json"
	fxPlan     = "../../../cmd/hdf/cmd/testdata/evidence-verify/plan.json"
	fxEvidence = "../../../cmd/hdf/cmd/testdata/evidence-verify/evidence.json"
	fxResults  = "../../../cmd/hdf/cmd/testdata/evidence-verify/rhel9-results.json"
	// A real DISA STIG checklist (Firefox) converted to HDF — carries one
	// effective notReviewed requirement (V-251559).
	fxCklResults = "../../../../hdf-converters/converters/ckl-to-hdf/fixtures/expected/firefox-stig.ckl.hdf.json"
	// A results doc carrying one agent-attributed and one system-attributed
	// override (the §3 detective-count fixture).
	fxAgentOverrides = "../tools/testdata/compliance-results.json"
	// A real grype scan → HDF with many uniform CVE requirements — a large
	// uniform array that gives TOON a fair chance for the §11 measurement.
	fxGrypeLarge = "../../../../hdf-converters/converters/grype-to-hdf/fixtures/expected/tensorflow.json.hdf.json"
	// The real openvex→HDF expected amendments (overrides target CVE-2024-1000/2000).
	fxOpenvexAmendments = "../../../../hdf-converters/converters/openvex-to-hdf/fixtures/expected/multi-status.openvex.json.hdf.json"
	fxDiffFrom          = "../tools/testdata/diff-from.json"
	fxDiffTo            = "../tools/testdata/diff-to.json"
	fxVEX               = "../../../../hdf-converters/converters/openvex-to-hdf/fixtures/input/multi-status.openvex.json"
	// A schema-valid results scaffold paired with the real multi-status VEX: its
	// requirement IDs (CVE-2024-1000/2000) match the VEX's targets, so applying
	// the VEX-derived amendments actually changes a requirement.
	fxVexResults = "testdata/vex-results.json"
	fxBigScan    = "../../../../hdf-fixtures/inspec/wrapper.json"
	// A real small gosec scan (raw tool output) for the hdf_convert golden.
	fxGosecRaw = "../../../../hdf-converters/converters/gosec-to-hdf/fixtures/input/grype-gosec.json"
)

// stageRoot makes a fresh HDF_MCP_ROOT and stages the given real fixtures into
// it, returning the root. Each pair is {sourcePath, destName}. A missing source
// skips the test (fixtures may be absent in a partial checkout).
func stageRoot(t *testing.T, pairs ...[2]string) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	for _, p := range pairs {
		b, err := os.ReadFile(p[0])
		if err != nil {
			t.Skipf("fixture %s unavailable: %v", p[0], err)
		}
		if err := os.WriteFile(filepath.Join(root, p[1]), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
