package evals

import (
	"encoding/json"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/evalharness"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	toon "github.com/toon-format/toon-go"
)

// TestTOON_DeltaByShape measures the JSON-vs-TOON token delta on every tool's
// REAL response shape (§11), the record behind the decision NOT to wire TOON into
// the tools. TOON's win requires uniform arrays of flat objects; HDF responses do
// not hold that shape well enough. Measured on real fixtures: concise hdf_query is
// only mildly positive (below the §11 ~20% bar) and hdf_diff / hdf_compliance are
// NEGATIVE (TOON makes them larger). This is a measurement that records a
// decision, not a pass/fail assertion; only a broken measurement fails.
func TestTOON_DeltaByShape(t *testing.T) {
	measure := func(label string, v any) {
		jb, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s json: %v", label, err)
		}
		ts, err := toon.MarshalString(v)
		if err != nil {
			t.Fatalf("%s toon: %v", label, err)
		}
		jt, err := evalharness.CountTokens(string(jb))
		if err != nil {
			t.Fatal(err)
		}
		tt, err := evalharness.CountTokens(ts)
		if err != nil {
			t.Fatal(err)
		}
		if jt == 0 || tt == 0 {
			t.Fatalf("%s: empty payload — measurement invalid", label)
		}
		t.Logf("%-30s json=%6d tok  toon=%6d tok  reduction=%+.1f%%", label, jt, tt, float64(jt-tt)/float64(jt)*100)
	}

	for _, verb := range []string{"concise", "full"} {
		stageRoot(t, [2]string{fxGrypeLarge, "q.json"})
		sc := structured(t, driveCalls(t, []call{{Tool: "hdf_query", Args: map[string]any{
			"source": map[string]any{"path": "q.json"}, "verbosity": verb,
		}}})[0])
		if rows, ok := sc["requirements"].([]any); ok && len(rows) > 0 {
			measure("query "+verb, rows)
		}
	}

	stageRoot(t, [2]string{fxDiffFrom, "from.json"}, [2]string{fxDiffTo, "to.json"})
	dsc := structured(t, driveCalls(t, []call{{Tool: "hdf_diff", Args: map[string]any{
		"from": map[string]any{"path": "from.json"}, "to": map[string]any{"path": "to.json"},
	}}})[0])
	if changes, ok := dsc["changes"].([]any); ok && len(changes) > 0 {
		measure("diff changes", changes)
	}

	stageRoot(t, [2]string{fxAgentOverrides, "c.json"})
	csc := structured(t, driveCalls(t, []call{{Tool: "hdf_compliance", Args: map[string]any{
		"source": map[string]any{"path": "c.json"}, "groupBy": "nistFamily",
	}}})[0])
	measure("compliance rollup", csc)
}

// queryRows drives hdf_query (full verbosity) on a staged fixture and returns
// the requirement rows the server produced — the real concise-query row shape,
// not a re-implementation.
func queryRows(t *testing.T, results string) []any {
	t.Helper()
	stageRoot(t, [2]string{results, "q.json"})
	resp := driveCalls(t, []call{{Tool: "hdf_query", Args: map[string]any{
		"source": map[string]any{"path": "q.json"}, "verbosity": "full",
	}}})
	sc := structured(t, resp[0])
	rowsRaw, _ := sc["requirements"].([]any)
	if len(rowsRaw) == 0 {
		t.Skip("fixture produced no query rows")
	}
	return rowsRaw
}

// TestTOON_QueryDelta measures the JSON-vs-TOON token delta on a real hdf_query
// response (§11). The same rows are encoded both ways through the server's own
// respond serializer; the reduction is logged for the card notes. Per §11, a
// reduction below ~20% means TOON is not worth defaulting on for hdf_query.
func TestTOON_QueryDelta(t *testing.T) {
	rows := queryRows(t, fxGrypeLarge)

	jsonRes, err := respond.Serialize("requirements", rows, respond.Options{
		Verbosity: respond.Full, Encoding: respond.JSON, Total: len(rows),
	})
	if err != nil {
		t.Fatal(err)
	}
	toonRes, err := respond.Serialize("requirements", rows, respond.Options{
		Verbosity: respond.Full, Encoding: respond.TOON, Total: len(rows),
	})
	if err != nil {
		t.Fatal(err)
	}

	jt, err := evalharness.CountTokens(jsonRes.Payload)
	if err != nil {
		t.Fatal(err)
	}
	tt, err := evalharness.CountTokens(toonRes.Payload)
	if err != nil {
		t.Fatal(err)
	}

	reduction := float64(jt-tt) / float64(jt) * 100
	t.Logf("TOON measurement on hdf_query (%d rows): json=%d tok, toon=%d tok, reduction=%.1f%% — §11 threshold ~20%%",
		len(rows), jt, tt, reduction)

	// This is a MEASUREMENT that records a decision (§11), not a pass/fail
	// assertion — a negative delta is itself a valid finding (drop TOON). Only a
	// broken measurement (empty payload) fails.
	if jsonRes.Payload == "" || toonRes.Payload == "" {
		t.Fatal("serialization produced an empty payload — measurement is invalid")
	}
	if reduction < 20 {
		t.Logf("§11 DECISION: reduction %.1f%% is below ~20%% — TOON stays opt-in, not defaulted for hdf_query", reduction)
	} else {
		t.Logf("§11: reduction %.1f%% meets the ~20%% bar — TOON is worth offering on hdf_query", reduction)
	}
}
