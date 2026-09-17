package tools

import (
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
)

func pathSources(paths ...string) []handle.Source {
	out := make([]handle.Source, 0, len(paths))
	for _, p := range paths {
		out = append(out, handle.Source{Path: p})
	}
	return out
}

// Compliance over a set is the compliance of the combined view: ZAP webgoat (28
// requirements, all failed) + grype tensorflow (26: 12 failed and 14
// notReviewed, of which 2 failed and 2 notReviewed sit at impact 0 and resolve
// to notApplicable) → 54 requirements, failed 38, skipped 12, no_impact 4, 0%
// compliant. The same figures hdf_aggregate reports for the same pair (its test
// computed them from the fixture JSON).
func TestCompliance_MultiSource_CountsOverTheSet(t *testing.T) {
	_, zap, grype := threeScannerSources(t)
	res, out := callCompliance(t, complianceInput{Sources: pathSources(zap, grype)})
	if res.IsError {
		t.Fatalf("compliance over the set errored: %s", payloadText(t, res))
	}
	c := out.Counts
	if c["failed"]["total"] != 38 || c["skipped"]["total"] != 12 || c["no_impact"]["total"] != 4 {
		t.Errorf("counts = failed %d / skipped %d / no_impact %d, want 38 / 12 / 4", c["failed"]["total"], c["skipped"]["total"], c["no_impact"]["total"])
	}
	if out.Compliance != 0 {
		t.Errorf("compliance = %v, want 0", out.Compliance)
	}
	if out.Handle != "" || len(out.Sources) != 2 || out.Sources[1].Index != 1 || out.Sources[1].Handle == "" {
		t.Errorf("envelope must name the two members and omit handle, got handle %q sources %+v", out.Handle, out.Sources)
	}
	if out.DocType != "results" {
		t.Errorf("docType = %q, want results", out.DocType)
	}
}

// groupBy=baseline over a set is one group per input baseline — five here (four
// ZAP sites, one grype image) — each under its <tool>/<original> name with its
// position in the view, and the groups partition the failed count exactly.
func TestCompliance_MultiSource_GroupByBaselineIsOneGroupPerInputBaseline(t *testing.T) {
	_, zap, grype := threeScannerSources(t)
	_, out := callCompliance(t, complianceInput{Sources: pathSources(zap, grype), GroupBy: "baseline"})
	if len(out.Groups) != 5 {
		t.Fatalf("groups = %d, want 5", len(out.Groups))
	}
	seen := map[int]bool{}
	failed := 0
	tools := map[string]int{}
	for _, g := range out.Groups {
		if g.BaselineIndex == nil {
			t.Fatalf("group %q has no baselineIndex", g.Group)
		}
		seen[*g.BaselineIndex] = true
		failed += g.Counts["failed"]["total"]
		tool, _, ok := strings.Cut(g.Group, "/")
		if !ok {
			t.Fatalf("group %q is not a <tool>/<original> name", g.Group)
		}
		tools[tool]++
	}
	for i := 0; i < 5; i++ {
		if !seen[i] {
			t.Errorf("baselineIndex %d missing from groups %+v", i, out.Groups)
		}
	}
	if failed != 38 {
		t.Errorf("groups' failed totals sum to %d, want 38", failed)
	}
	if tools["owasp zap"] != 4 || tools["grype"] != 1 {
		t.Errorf("groups per tool = %v, want owasp zap 4, grype 1", tools)
	}
}

// A threshold applies over the set exactly as over one document (owner decision
// 2026-09-17: a threshold intended for combined data is legitimate). failed.total
// max 12 passes grype alone (12 failed) and fails the ZAP+grype set (38).
func TestCompliance_MultiSource_ThresholdAppliesOverTheView(t *testing.T) {
	_, zap, grype := threeScannerSources(t)
	spec := &thresholdInput{Inline: map[string]any{"failed": map[string]any{"total": map[string]any{"max": 12}}}}
	_, alone := callCompliance(t, complianceInput{Source: pathSources(grype)[0], Threshold: spec})
	if alone.ThresholdVerdict == nil || !alone.ThresholdVerdict.Pass {
		t.Fatalf("failed.total.max 12 must pass grype alone (12 failed), got %+v", alone.ThresholdVerdict)
	}
	res, set := callCompliance(t, complianceInput{Sources: pathSources(zap, grype), Threshold: spec})
	if res.IsError {
		t.Fatalf("a threshold over a set must be evaluated, not refused: %s", payloadText(t, res))
	}
	if set.ThresholdVerdict == nil || set.ThresholdVerdict.Pass || len(set.ThresholdVerdict.Failures) == 0 {
		t.Errorf("failed.total.max 12 must fail the set (38 failed) with failures, got %+v", set.ThresholdVerdict)
	}
	if !strings.Contains(strings.Join(set.ThresholdVerdict.Failures, " "), "38") {
		t.Errorf("the failure must name the set's failed count 38, got %v", set.ThresholdVerdict.Failures)
	}
}
