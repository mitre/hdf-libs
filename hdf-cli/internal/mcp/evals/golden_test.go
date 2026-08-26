package evals

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// stripVolatile recursively removes content-integrity keys (handle, sha256) that
// are not part of a response's shape and can fold in a stamped timestamp.
func stripVolatile(v any) any {
	switch n := v.(type) {
	case map[string]any:
		delete(n, "handle")
		delete(n, "sha256")
		for k := range n {
			n[k] = stripVolatile(n[k])
		}
		return n
	case []any:
		for i := range n {
			n[i] = stripVolatile(n[i])
		}
		return n
	default:
		return v
	}
}

// TestGolden_ToolResponses captures a real-fixture response for every tool and
// asserts it against a committed golden, so any shape change surfaces in review
// rather than silently. Responses are deterministic (handles and hashes are
// content-derived), so the golden is stable. Regenerate intentionally with
// REGEN_GOLDEN=1 when the surface changes.
func TestGolden_ToolResponses(t *testing.T) {
	got := map[string]any{}
	src := func(p string) map[string]any { return map[string]any{"path": p} }

	capture := func(name string, c call, staging ...[2]string) {
		stageRoot(t, staging...)
		got[name] = structured(t, driveCalls(t, []call{c})[0])
	}

	capture("hdf_open", call{"hdf_open", map[string]any{"source": src("system.json")}}, [2]string{fxSystem, "system.json"})
	capture("hdf_inspect", call{"hdf_inspect", map[string]any{"source": src("system.json")}}, [2]string{fxSystem, "system.json"})
	capture("hdf_query", call{"hdf_query", map[string]any{"source": src("r.json"), "status": []any{"failed"}}}, [2]string{fxAgentOverrides, "r.json"})
	capture("hdf_compliance", call{"hdf_compliance", map[string]any{"source": src("r.json")}}, [2]string{fxAgentOverrides, "r.json"})
	capture("hdf_diff", call{"hdf_diff", map[string]any{"from": src("from.json"), "to": src("to.json")}},
		[2]string{fxDiffFrom, "from.json"}, [2]string{fxDiffTo, "to.json"})
	capture("hdf_validate", call{"hdf_validate", map[string]any{"source": src("system.json"), "mode": "schema"}}, [2]string{fxSystem, "system.json"})
	capture("hdf_author", call{"hdf_author", map[string]any{
		"docType": "system", "name": "S", "content": []any{map[string]any{"type": "host", "name": "h1"}}}}, [2]string{fxSystem, "system.json"})
	capture("hdf_convert", call{"hdf_convert", map[string]any{"source": src("gosec.json"), "from": "gosec"}}, [2]string{fxGosecRaw, "gosec.json"})

	// hdf_apply_amendment is a two-stage flow (author writes the amendments file,
	// then apply reads it); capture apply's response.
	stageRoot(t, [2]string{fxVEX, "vex.json"}, [2]string{fxVexResults, "results.json"})
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	driveCalls(t, []call{{"hdf_author", map[string]any{
		"docType": "amendments", "name": "V", "source": src("vex.json"),
		"expiresAt": "2099-12-31T00:00:00Z", "output": "amendments.json"}}})
	got["hdf_apply_amendment"] = structured(t, driveCalls(t, []call{{"hdf_apply_amendment", map[string]any{
		"results": src("results.json"), "amendments": src("amendments.json")}}})[0])

	// Strip content-integrity values that are not "shape": handle and sha256 are
	// content-derived, and for authored/applied docs they fold in the judgment
	// path's stamped appliedAt — the real when-applied action timestamp that is
	// ADR-0007 §12's ONE deliberate exception to output determinism, so they vary
	// run-to-run by design (not a hidden non-determinism). The golden asserts the
	// response STRUCTURE and its stable values, which is what must surface in
	// review; the appliedAt exception is covered by the determinism-suite test
	// TestDeterminism_JudgmentPathStampsActionTimestamp.
	for k := range got {
		got[k] = stripVolatile(got[k])
	}

	want := map[string]any{"hdf_open": nil, "hdf_inspect": nil, "hdf_query": nil, "hdf_compliance": nil,
		"hdf_diff": nil, "hdf_validate": nil, "hdf_author": nil, "hdf_convert": nil, "hdf_apply_amendment": nil}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("golden is missing a captured response for %s", k)
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(got); err != nil {
		t.Fatal(err)
	}
	goldenPath := filepath.Join("testdata", "tool-responses.golden.json")

	if os.Getenv("REGEN_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Skip("regenerated tool-responses golden")
	}

	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (regenerate with REGEN_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(golden), bytes.TrimSpace(buf.Bytes())) {
		t.Errorf("tool responses differ from the golden — update intentionally with REGEN_GOLDEN=1 when the surface changes.\nlive:\n%s", buf.String())
	}
}

// TestGolden_AmendmentsRoundTrip pins the FULL authored override bytes on the
// judgment path, field-for-field. The response golden (TestGolden_ToolResponses)
// strips handle+sha256, and for author/apply those are the only content-derived
// values — so without this the authored amendment bytes are unpinned and an
// optional/semantic field silently dropped or altered while STILL schema-valid
// (e.g. reason, status) would slip through (bead 4908.16). appliedAt is the one
// deliberately-volatile field — the judgment path's real action timestamp
// (ADR-0007 §12) — so it is asserted present, then normalized out before the
// byte-for-byte comparison of everything else.
func TestGolden_AmendmentsRoundTrip(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := stageRoot(t)
	driveCalls(t, []call{{"hdf_author", map[string]any{
		"docType": "amendments", "name": "A",
		"content": []any{map[string]any{
			"type": "riskAdjustment", "requirementId": "CVE-2024-1000", "status": "notApplicable",
			"reason": "compensating control in place", "expiresAt": "2099-12-31T00:00:00Z",
		}},
		"output": "amendments.json",
	}}})

	b, err := os.ReadFile(filepath.Join(root, "amendments.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	overrides, ok := doc["overrides"].([]any)
	if !ok || len(overrides) != 1 {
		t.Fatalf("expected exactly one authored override, got %v", doc["overrides"])
	}
	got, ok := overrides[0].(map[string]any)
	if !ok {
		t.Fatalf("override is not an object: %v", overrides[0])
	}

	if ts, _ := got["appliedAt"].(string); ts == "" {
		t.Fatal("authored override must carry a non-empty appliedAt (judgment-path action timestamp)")
	}
	delete(got, "appliedAt")

	want := map[string]any{
		"type":          "riskAdjustment",
		"requirementId": "CVE-2024-1000",
		"status":        "notApplicable",
		"reason":        "compensating control in place",
		"expiresAt":     "2099-12-31T00:00:00Z",
		"appliedBy": map[string]any{
			"identifier": "hdf-mcp",
			"type":       "agent",
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("authored override bytes drifted from the pinned round-trip:\n want %#v\n  got %#v", want, got)
	}
}
