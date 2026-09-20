package tools

import (
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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
	if out.Handle != "" || len(out.Sources) != 2 || out.Sources[1].Index != 1 || out.Sources[1].Source != grype {
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

// groupBy=tool over a set is one group per scanner, keyed by the tool label the
// engine Merge stamps on every baseline (ADR-0016 §3) — never by parsing the
// baseline name. Expected from the fixtures, by EFFECTIVE status: gosec 4
// requirements, 3 failed and 1 passed (G304 carries a status override to
// passed); ZAP 28 all failed; grype 26 = 10 failed + 12 skipped + 4 no_impact.
// The groups partition the set: failed sums to 41, rows to 58.
func TestCompliance_MultiSource_GroupByTool(t *testing.T) {
	gosec, zap, grype := threeScannerSources(t)
	res, out := callCompliance(t, complianceInput{Sources: pathSources(gosec, zap, grype), GroupBy: "tool"})
	if res.IsError {
		t.Fatalf("groupBy tool errored: %s", payloadText(t, res))
	}
	want := map[string]map[string]int{
		"gosec":     {"failed": 3, "passed": 1, "rows": 4},
		"owasp zap": {"failed": 28, "rows": 28},
		"grype":     {"failed": 10, "skipped": 12, "no_impact": 4, "rows": 26},
	}
	if len(out.Groups) != 3 {
		t.Fatalf("groups = %+v, want exactly gosec / owasp zap / grype", out.Groups)
	}
	failed, rows := 0, 0
	for _, g := range out.Groups {
		w, ok := want[g.Group]
		if !ok {
			t.Errorf("unexpected group %q", g.Group)
			continue
		}
		if g.BaselineIndex != nil {
			t.Errorf("group %q: baselineIndex is baseline mode's, must be absent here", g.Group)
		}
		got := 0
		for status, sev := range g.Counts {
			got += sev["total"]
			if sev["total"] != w[status] { // every status, including the zero ones
				t.Errorf("group %q %s.total = %d, want %d", g.Group, status, sev["total"], w[status])
			}
		}
		if got != w["rows"] {
			t.Errorf("group %q rows = %d, want %d", g.Group, got, w["rows"])
		}
		failed += g.Counts["failed"]["total"]
		rows += got
	}
	if failed != 41 || rows != 58 {
		t.Errorf("groups sum to failed %d / rows %d, want 41 / 58 (a partition of the set)", failed, rows)
	}
	if out.GroupBy != "tool" {
		t.Errorf("groupBy echoed as %q", out.GroupBy)
	}
}

// A single document carries no tool label (the label is stamped only when a
// set is combined), so groupBy=tool yields one group, "unlabeled" — not a group
// named after a baseline-name prefix and not an error. The grype fixture's
// baseline is named "tensorflow/tensorflow:latest": a prefix parser would
// answer "tensorflow", which is exactly the anti-pattern this pins out.
func TestCompliance_SingleSource_GroupByToolIsUnlabeled(t *testing.T) {
	_, _, grype := threeScannerSources(t)
	res, out := callCompliance(t, complianceInput{Source: pathSources(grype)[0], GroupBy: "tool"})
	if res.IsError {
		t.Fatalf("groupBy tool on one document errored: %s", payloadText(t, res))
	}
	if len(out.Groups) != 1 || out.Groups[0].Group != "unlabeled" || out.Groups[0].Counts["failed"]["total"] != 10 {
		t.Errorf("groups = %+v, want one group unlabeled with 10 failed (not a group named after the tensorflow/ prefix)", out.Groups)
	}
}

// The tool partition reads the label and only the label: a baseline whose name
// prefix and tool label disagree groups under the label, and the fallback
// applies to a label that is absent, not to a name without a slash.
func TestPartitionResults_ToolUsesLabelNotNamePrefix(t *testing.T) {
	req := func(id string) hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{ID: id, Impact: 0.5, Results: []hdf.RequirementResult{{Status: hdf.Failed}}}
	}
	results := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{
		{Name: "zap/site A", Labels: map[string]string{hdfengine.LabelTool: "owasp zap"}, Requirements: []hdf.EvaluatedRequirement{req("a")}},
		{Name: "grype/image", Labels: map[string]string{hdfengine.LabelTool: "owasp zap"}, Requirements: []hdf.EvaluatedRequirement{req("b")}},
		{Name: "nessus/host", Requirements: []hdf.EvaluatedRequirement{req("c"), req("d")}},
	}}
	parts, gerr := partitionResults(results, "tool")
	if gerr != nil {
		t.Fatal(gerr)
	}
	got := map[string]int{}
	for _, p := range parts {
		got[p.Group] = len(p.Results.Baselines[0].Requirements)
	}
	want := map[string]int{"owasp zap": 2, "unlabeled": 2}
	if len(got) != len(want) || got["owasp zap"] != 2 || got["unlabeled"] != 2 {
		t.Errorf("tool partitions = %v, want %v (label wins over the zap/ and grype/ prefixes; nessus/ without a label is unlabeled)", got, want)
	}
}

// groupBy=cwe groups by each requirement's cwe[] values, normalized to numbers
// (the CWE-N spellings meet as one group), multi-membership like nistFamily, with
// "unmapped" for a requirement citing none. Expected from the fixtures: ZAP's
// 28 rows cite 8 distinct CWEs (16 ×5, 20, 89, 200 ×16, 352 ×2, 425, 541, 933);
// gosec's 4 and grype's 26 cite none → unmapped 30.
func TestCompliance_MultiSource_GroupByCWE(t *testing.T) {
	gosec, zap, grype := threeScannerSources(t)
	res, out := callCompliance(t, complianceInput{Sources: pathSources(gosec, zap, grype), GroupBy: "cwe"})
	if res.IsError {
		t.Fatalf("groupBy cwe errored: %s", payloadText(t, res))
	}
	want := map[string]int{"16": 5, "20": 1, "89": 1, "200": 16, "352": 2, "425": 1, "541": 1, "933": 1, "unmapped": 30}
	if len(out.Groups) != len(want) {
		t.Fatalf("got %d groups %+v, want %d", len(out.Groups), out.Groups, len(want))
	}
	for _, g := range out.Groups {
		total := 0
		for _, sev := range g.Counts {
			total += sev["total"]
		}
		if w, ok := want[g.Group]; !ok || total != w {
			t.Errorf("group %q rows = %d, want %d (present: %v)", g.Group, total, w, ok)
		}
	}
	if out.Truncated {
		t.Errorf("nine groups over 58 rows must fit the concise budget, got truncated: %s", out.Notice)
	}
}
