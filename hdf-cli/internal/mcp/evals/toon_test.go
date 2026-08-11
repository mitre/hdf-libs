package evals

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/evalharness"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
)

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
