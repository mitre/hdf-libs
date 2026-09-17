package tools

import (
	"context"
	"encoding/json"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// TestFilterResultsToMatches_KeepsOnlyMatchedOnRepeatedIDs (js1nv.2): the
// projection from engine matches back to requirements must keep exactly the
// matched requirements. Keyed by (baseline name, id) it over-keeps: a limit-7
// match set that includes the first Grype/CVE-2024-7264 (position 6) but not
// the second (position 7) must project to 7 requirements, not 8.
func TestFilterResultsToMatches_KeepsOnlyMatchedOnRepeatedIDs(t *testing.T) {
	var results hdf.HDFResults
	if err := json.Unmarshal(readToolsFixture(t, "grype-duplicate-ids.json"), &results); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	matches := hdfengine.Filter(context.Background(), results, hdfengine.Options{
		Limit: 7, StatusOf: shared.RequirementEffectiveStatus,
	})
	if len(matches) != 7 {
		t.Fatalf("expected 7 matches, got %d", len(matches))
	}
	if matches[6].ID != "Grype/CVE-2024-7264" {
		t.Fatalf("fixture invariant: match 6 must be the first Grype/CVE-2024-7264, got %s", matches[6].ID)
	}
	kept := filterResultsToMatches(results, matches)
	n := 0
	var pkgs []string
	for _, b := range kept.Baselines {
		for _, r := range b.Requirements {
			n++
			if r.ID == "Grype/CVE-2024-7264" {
				if len(r.AffectedPackages) == 0 || r.AffectedPackages[0].Name == nil {
					t.Fatalf("fixture invariant: %s carries a named affected package", r.ID)
				}
				pkgs = append(pkgs, *r.AffectedPackages[0].Name)
			}
		}
	}
	if n != 7 {
		t.Errorf("projected %d requirements, want exactly the 7 matched", n)
	}
	if len(pkgs) != 1 || pkgs[0] != "curl" {
		t.Errorf("kept Grype/CVE-2024-7264 packages = %v, want only [curl] (position 6)", pkgs)
	}
}

// TestAggregate_TotalEqualsQueryTotal_OnRepeatedKeys (js1nv.2 AC 4): on the real
// Prisma fixture — 16 same-named baselines, repeated (name, id) pairs — the
// unfiltered hdf_aggregate total, its per-source count, and hdf_query's total
// all report the 94 requirements the document holds.
func TestAggregate_TotalEqualsQueryTotal_OnRepeatedKeys(t *testing.T) {
	srcs := sourcesUnderRoot(t, "duplicate-baselines.json")
	_, agg := callAggregate(t, aggregateInput{Sources: srcs})
	if agg.Aggregate.Total != 94 {
		t.Fatalf("aggregate total = %d, want 94", agg.Aggregate.Total)
	}
	if len(agg.PerSource) != 1 || agg.PerSource[0].Total != 94 || agg.PerSource[0].Counts["failed"]["total"] != 94 {
		t.Fatalf("per-source rollup = %+v, want one source with 94 matched / 94 failed", agg.PerSource)
	}
	_, q := callQuery(t, queryInput{Source: srcs[0], Limit: 1})
	if q.Total != 94 {
		t.Errorf("hdf_query total = %d, want 94 (equal to the aggregate total)", q.Total)
	}
}

// TestAggregate_MergedCountsAcrossSources pins the all-source rollup that goes
// through the engine Merge — the status × severity counts and compliance — on
// two real documents with different severity mixes, so a merge that dropped a
// source or a baseline would be caught here even though Aggregate.Total is
// summed independently. ZAP webgoat: 28 requirements; grype tensorflow: 26.
func TestAggregate_MergedCountsAcrossSources(t *testing.T) {
	srcs := sourcesUnderRoot(t, "zap-webgoat.json", "grype-duplicate-ids.json")
	_, out := callAggregate(t, aggregateInput{Sources: srcs})
	if out.Aggregate.Total != 54 {
		t.Fatalf("total = %d, want 54", out.Aggregate.Total)
	}
	c := out.Aggregate.Counts
	if c["failed"]["total"] != 38 || c["skipped"]["total"] != 12 || c["no_impact"]["total"] != 4 {
		t.Errorf("merged status counts = failed %d / skipped %d / no_impact %d, want 38 / 12 / 4", c["failed"]["total"], c["skipped"]["total"], c["no_impact"]["total"])
	}
	if got := c["failed"]["total"] + c["skipped"]["total"] + c["no_impact"]["total"] + c["passed"]["total"] + c["error"]["total"]; got != 54 {
		t.Errorf("merged counts sum to %d, want every one of the 54 requirements", got)
	}
	// Compliance is passed / (total − no_impact): 0 / 50 here.
	if out.Aggregate.Compliance != 0 {
		t.Errorf("compliance = %v, want 0 (no passed requirements)", out.Aggregate.Compliance)
	}
	// A severity filter narrows what is merged: critical+high across both docs.
	_, hi := callAggregate(t, aggregateInput{Sources: srcs, Severity: []string{"critical", "high"}})
	hc := hi.Aggregate.Counts
	statusSum := hc["failed"]["total"] + hc["skipped"]["total"] + hc["no_impact"]["total"] + hc["passed"]["total"] + hc["error"]["total"]
	if hi.Aggregate.Total != 9 || statusSum != 9 || hc["failed"]["total"] != 5 {
		t.Errorf("critical+high across sources = total %d, status sum %d, failed %d; want 9 / 9 / 5 (grype's not-reviewed and not-applicable highs are counted, not lost)", hi.Aggregate.Total, statusSum, hc["failed"]["total"])
	}
	// A source contributing zero matches is merged as an empty document and must
	// neither fail the call nor perturb the counts: every ZAP requirement is
	// failed, so a notReviewed filter matches nothing in ZAP and grype's 12.
	_, nr := callAggregate(t, aggregateInput{Sources: srcs, Status: []string{"notReviewed"}})
	if nr.Aggregate.Total != 12 || nr.Aggregate.Counts["skipped"]["total"] != 12 || nr.Aggregate.Counts["failed"]["total"] != 0 {
		t.Errorf("notReviewed across sources = total %d / skipped %d / failed %d, want 12 / 12 / 0 (ZAP contributes nothing)", nr.Aggregate.Total, nr.Aggregate.Counts["skipped"]["total"], nr.Aggregate.Counts["failed"]["total"])
	}
	if len(nr.PerSource) != 2 || nr.PerSource[0].Total != 0 || nr.PerSource[1].Total != 12 {
		t.Errorf("per-source: %+v, want ZAP 0 and grype 12", nr.PerSource)
	}
}
