package evals

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// mintEmptyPathHandle builds a well-formed, empty-path (content-addressed) handle
// over bytes that were never registered in the session's cache — so resolving it
// must miss.
func mintEmptyPathHandle(t *testing.T, docType string) string {
	t.Helper()
	enc, err := handle.Encode(handle.Compute("", []byte(`{"components":[],"unregistered":true}`), docType, hdfengine.Version()))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// callToolStructured drives one tool over the shared-server session and returns
// its structuredContent as a map. Fails on an isError result.
func callToolStructured(t *testing.T, cs *sdkmcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s transport error: %v", name, err)
	}
	if res.IsError {
		txt := ""
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*sdkmcp.TextContent); ok {
				txt = tc.Text
			}
		}
		t.Fatalf("%s returned isError: %s", name, txt)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal %s structured content: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s structured content: %v", name, err)
	}
	return m
}

// TestJobi1_ChainWritesDisabled is the card's headline guarantee: with
// HDF_MCP_ENABLE_WRITES unset (the default) and NO output on any tool, the full
// author→apply→compliance pipeline composes entirely in memory via
// content-addressed handles, and ZERO files are written (jobi.1 / D1). Before the
// fix the authored handle carried an empty path and apply returned PATH_DENIED.
func TestJobi1_ChainWritesDisabled(t *testing.T) {
	// Writes disabled — the default posture the card targets.
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	root := stageRoot(t, [2]string{fxVexResults, "results.json"})
	cs := connectSession(t)

	// 1. Author an agent override (judgment path), NO output → cache-backed handle.
	aout := callToolStructured(t, cs, "hdf_author", map[string]any{
		"docType": "amendments", "name": "A",
		"content": []any{map[string]any{
			"type": "riskAdjustment", "requirementId": "CVE-2024-1000", "status": "notApplicable",
			"reason": "compensating control in place", "expiresAt": "2099-12-31T00:00:00Z",
		}},
	})
	amendHandle, _ := aout["handle"].(string)
	if amendHandle == "" {
		t.Fatal("author must return a handle")
	}

	// 2. Apply that authored handle to the results, NO output → cache-backed handle.
	pout := callToolStructured(t, cs, "hdf_apply_amendment", map[string]any{
		"results":    map[string]any{"path": "results.json"},
		"amendments": map[string]any{"handle": amendHandle},
	})
	appliedHandle, _ := pout["handle"].(string)
	if appliedHandle == "" {
		t.Fatal("apply must return a handle")
	}

	// 3. Compliance on the applied handle → counts the one agent override.
	cout := callToolStructured(t, cs, "hdf_compliance", map[string]any{
		"source": map[string]any{"handle": appliedHandle},
	})
	ao, ok := cout["agentOverrides"].(map[string]any)
	if !ok || ao["count"].(float64) != 1 {
		t.Fatalf("post-apply agentOverrides.count via in-memory chain must be 1, got %v", cout["agentOverrides"])
	}

	// ZERO files written: only the staged input remains under the root.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "results.json" {
			t.Errorf("writes disabled but a file was created: %s", e.Name())
		}
	}
}

// TestJobi1_HandleRoundTripMatrix is the jobi success criterion: every tool that
// mints a handle has that handle resolved by another tool in the surface — no
// unconsumable handle escapes (writes disabled, all in-memory).
func TestJobi1_HandleRoundTripMatrix(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	stageRoot(t,
		[2]string{fxSystem, "system.json"},
		[2]string{fxAgentOverrides, "r.json"},
		[2]string{fxGosecRaw, "gosec.json"},
	)
	cs := connectSession(t)

	// hdf_open → hdf_inspect
	openH, _ := callToolStructured(t, cs, "hdf_open", map[string]any{"source": map[string]any{"path": "system.json"}})["handle"].(string)
	if openH == "" || callToolStructured(t, cs, "hdf_inspect", map[string]any{"source": map[string]any{"handle": openH}})["docType"] != "system" {
		t.Errorf("hdf_open handle must resolve in hdf_inspect")
	}

	// hdf_convert (no output) → hdf_query, resolved from the in-memory cache
	convH, _ := callToolStructured(t, cs, "hdf_convert", map[string]any{"source": map[string]any{"path": "gosec.json"}, "from": "gosec"})["handle"].(string)
	if convH == "" {
		t.Fatal("convert must return a handle")
	}
	if q := callToolStructured(t, cs, "hdf_query", map[string]any{"source": map[string]any{"handle": convH}}); q["total"] == nil {
		t.Errorf("hdf_convert cache-backed handle must resolve in hdf_query, got %v", q)
	}

	// hdf_author (no output) → hdf_inspect, resolved from the in-memory cache
	authH, _ := callToolStructured(t, cs, "hdf_author", map[string]any{
		"docType": "system", "name": "S", "content": []any{map[string]any{"type": "host", "name": "h1"}},
	})["handle"].(string)
	if authH == "" || callToolStructured(t, cs, "hdf_inspect", map[string]any{"source": map[string]any{"handle": authH}})["docType"] != "system" {
		t.Errorf("hdf_author cache-backed handle must resolve in hdf_inspect")
	}
}

// TestJobi1_CacheMiss confirms an unresolvable cache-backed handle returns the
// CACHE_MISS taxonomy code with re-author/persist guidance — never PATH_DENIED
// or DOCUMENT_NOT_FOUND (the D2 empty-path misdiagnosis fix).
func TestJobi1_CacheMiss(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	stageRoot(t)
	cs := connectSession(t)

	// A well-formed handle for content that was never registered (fresh session).
	bogus := mintEmptyPathHandle(t, "system")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "hdf_inspect", Arguments: map[string]any{"source": map[string]any{"handle": bogus}},
	})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError {
		t.Fatal("an unregistered cache-backed handle must be an error")
	}
	txt := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*sdkmcp.TextContent); ok {
			txt = tc.Text
		}
	}
	var body struct{ Code, NextCall string }
	_ = json.Unmarshal([]byte(txt), &body)
	if body.Code != "CACHE_MISS" {
		t.Errorf("code = %q, want CACHE_MISS (not PATH_DENIED/DOCUMENT_NOT_FOUND): %s", body.Code, txt)
	}
	if !strings.Contains(body.NextCall, "output") {
		t.Errorf("CACHE_MISS nextCall must guide to re-author or set output, got %q", body.NextCall)
	}
}

// TestJobi1_OutputRequestedButWritesDisabled_HandleResolvesFromCache closes the
// coverage gap on the exact root bug: when output IS requested but writes are
// disabled, nothing is written, so the handle must carry the (empty) written
// path and resolve from the cache — NOT the requested output path. Minting the
// handle from in.Output (the pre-fix bug) would point it at a file that will
// never exist, and hdf_inspect would return DOCUMENT_NOT_FOUND.
func TestJobi1_OutputRequestedButWritesDisabled_HandleResolvesFromCache(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	stageRoot(t)
	cs := connectSession(t)

	aout := callToolStructured(t, cs, "hdf_author", map[string]any{
		"docType": "system", "name": "S",
		"content": []any{map[string]any{"type": "host", "name": "h1"}},
		"output":  "probe.json", // requested, but writes disabled → never written
	})
	if aout["writesDisabled"] != true {
		t.Fatalf("expected a WRITES_DISABLED preview, got %v", aout)
	}
	if op, _ := aout["outputPath"].(string); op != "" {
		t.Fatalf("writes disabled — nothing should be written, got outputPath=%q", op)
	}
	h, _ := aout["handle"].(string)
	if callToolStructured(t, cs, "hdf_inspect", map[string]any{"source": map[string]any{"handle": h}})["docType"] != "system" {
		t.Error("an output-requested-but-unwritten handle must resolve from the cache, not the requested (nonexistent) path")
	}
}
