package tools

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// This is the cross-tool regression guard (hdf-libs-lj0g.1). Every other MCP tool
// test verifies one tool in isolation, which is exactly why three tools could
// report a document's status one way while hdf_query reported it another and ship
// (hdf-libs-lj0g.4). This harness loads one fixture, derives the canonical
// distribution from the document itself, and asserts every status-reporting
// surface matches — so a re-fork of the status OR severity convention on any tool
// fails the build.
//
// Pre-fix demonstration (lj0g.4, verified live on the corpus doc
// vanilla-container-none-debian-11-8230d95.json.hdf.json): before the effective-
// status fix, hdf_open reported {notApplicable:0, notReviewed:119} and
// hdf_compliance {no_impact:0, skipped:119} while the document's own
// effectiveStatus gave {notApplicable:113, notReviewed:6}. This harness asserts
// against that derived ground truth, so it FAILS on that pre-fix code.
//
// Vocabulary note: hdf_compliance.counts uses SAF keys (skipped/no_impact); they
// are translated to the schema vocabulary here per the documented mapping
// (lj0g.7). Severity note: hdf_open/hdf_inspect expose status only (no
// per-requirement severity), so the severity distribution is asserted for the
// surfaces that expose it (hdf_query, hdf_compliance) — an explicit, documented
// exception, not a skipped assertion.

// groundTruth computes the canonical effective-status and severity distribution
// for a results document straight from its requirements (impact-0 → notApplicable
// and overrides via hdfutil.ComputeEffectiveStatus; severity via
// hdfengine.DeriveSeverity). Deriving it from the fixture — not a hand-written
// literal — keeps the fixture and the expectation from drifting apart.
func groundTruth(t *testing.T, content []byte) (status, severity map[string]int) {
	t.Helper()
	var r hdf.HDFResults
	if err := json.Unmarshal(content, &r); err != nil {
		t.Fatalf("ground truth parse: %v", err)
	}
	status, severity = zeroStatus(), map[string]int{}
	for i := range r.Baselines {
		for j := range r.Baselines[i].Requirements {
			req := r.Baselines[i].Requirements[j]
			status[hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(req), time.Time{})]++
			severity[hdfengine.DeriveSeverity(req.Impact, req.Severity)]++
		}
	}
	return status, severity
}

func zeroStatus() map[string]int {
	return map[string]int{"passed": 0, "failed": 0, "notApplicable": 0, "notReviewed": 0, "error": 0}
}

// mapsEqual reports whether two int-valued maps have identical non-zero entries.
func mapsEqual(a, b map[string]int) bool {
	nz := func(m map[string]int) map[string]int {
		out := map[string]int{}
		for k, v := range m {
			if v != 0 {
				out[k] = v
			}
		}
		return out
	}
	na, nb := nz(a), nz(b)
	if len(na) != len(nb) {
		return false
	}
	for k, v := range na {
		if nb[k] != v {
			return false
		}
	}
	return true
}

func TestAllToolsAgreeOnStatusDistribution(t *testing.T) {
	fixtures := []struct {
		name, file string
	}{
		{"impact-zero (impact-0 + explicit STIG severity)", "impact-zero.json"},
		{"severity-mix (all impact×tag combinations)", "severity-mix.json"},
		{"multi-baseline results", "query-results.json"},
		{"results with agent + system overrides", "compliance-results.json"},
	}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			content := readToolsFixture(t, fx.file)
			gtStatus, gtSev := groundTruth(t, content)
			path := writeRoot(t, fx.file, content)
			src := handle.Source{Path: path}

			// hdf_query — per-row status + severity.
			_, q := callQuery(t, queryInput{Source: src})
			qStatus, qSev := zeroStatus(), map[string]int{}
			for _, r := range q.Requirements {
				qStatus[r["status"].(string)]++
				qSev[r["severity"].(string)]++
			}
			if !mapsEqual(qStatus, gtStatus) {
				t.Errorf("hdf_query status = %v, ground truth %v", qStatus, gtStatus)
			}
			if !mapsEqual(qSev, gtSev) {
				t.Errorf("hdf_query severity = %v, ground truth %v", qSev, gtSev)
			}

			// hdf_open — summary.statusBreakdown (status only).
			_, o := callOpen(t, openInput{Source: src})
			if sb, ok := o.Summary["statusBreakdown"].(map[string]int); !ok || !mapsEqual(sb, gtStatus) {
				t.Errorf("hdf_open statusBreakdown = %v, ground truth %v", o.Summary["statusBreakdown"], gtStatus)
			}

			// hdf_inspect — sum of per-baseline statusBreakdown (status only).
			_, ins := callInspect(t, inspectInput{Source: src})
			insStatus := zeroStatus()
			if baselines, ok := ins.Structure["baselines"].([]map[string]any); ok {
				for _, b := range baselines {
					if sb, ok := b["statusBreakdown"].(map[string]int); ok {
						for k, v := range sb {
							insStatus[k] += v
						}
					}
				}
			}
			if !mapsEqual(insStatus, gtStatus) {
				t.Errorf("hdf_inspect statusBreakdown = %v, ground truth %v", insStatus, gtStatus)
			}

			// hdf_compliance — counts, translating SAF vocabulary to schema (lj0g.7).
			_, c := callCompliance(t, complianceInput{Source: src})
			cStatus := map[string]int{
				"passed":        c.Counts["passed"]["total"],
				"failed":        c.Counts["failed"]["total"],
				"notApplicable": c.Counts["no_impact"]["total"],
				"notReviewed":   c.Counts["skipped"]["total"],
				"error":         c.Counts["error"]["total"],
			}
			if !mapsEqual(cStatus, gtStatus) {
				t.Errorf("hdf_compliance status = %v, ground truth %v", cStatus, gtStatus)
			}
			cSev := map[string]int{}
			for _, buckets := range c.Counts {
				for sev, n := range buckets {
					if sev != "total" {
						cSev[sev] += n
					}
				}
			}
			if !mapsEqual(cSev, gtSev) {
				t.Errorf("hdf_compliance severity = %v, ground truth %v", cSev, gtSev)
			}

			// hdf_diff — shares the effective-status seam (diff.ComputeEffectiveStatus
			// delegates to hdfutil.ComputeEffectiveStatus). It produces comparisons,
			// not a document snapshot, so we exercise its effective-status function
			// over the same requirements and assert the distribution matches.
			var r hdf.HDFResults
			if err := json.Unmarshal(content, &r); err != nil {
				t.Fatal(err)
			}
			diffStatus := zeroStatus()
			for i := range r.Baselines {
				for j := range r.Baselines[i].Requirements {
					diffStatus[diff.ComputeEffectiveStatus(r.Baselines[i].Requirements[j], "")]++
				}
			}
			if !mapsEqual(diffStatus, gtStatus) {
				t.Errorf("hdf_diff effective-status = %v, ground truth %v", diffStatus, gtStatus)
			}
		})
	}
}
