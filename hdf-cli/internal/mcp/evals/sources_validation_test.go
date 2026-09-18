package evals

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestSourcesOnly_PassesSDKArgumentValidation pins a defect the tools package's
// handler-level tests cannot see: the SDK validates tools/call arguments against
// the schema derived from the input struct BEFORE the handler runs, and with
// `source` schema-required a sources[]-only call was refused at the door with
// `required: missing properties: ["source"]` (found by the card's live stdio
// test, 2026-09-17). Exactly-one-of source/sources is the handler's rule and
// cannot be expressed to the reflector, so neither field may be required.
func TestSourcesOnly_PassesSDKArgumentValidation(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"sarif-gosec.json", "zap-webgoat.json"} {
		b, err := os.ReadFile(filepath.Join("..", "tools", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HDF_MCP_ROOT", root)
	cs := connectSession(t)
	sources := []any{map[string]any{"path": "sarif-gosec.json"}, map[string]any{"path": "zap-webgoat.json"}}

	q := callToolStructured(t, cs, "hdf_query", map[string]any{"sources": sources, "limit": 1})
	if q["total"] != float64(32) {
		t.Errorf("hdf_query over the set: total = %v, want 32 (4 gosec + 28 ZAP)", q["total"])
	}
	if _, ok := q["handle"]; ok {
		t.Error("multi-source hdf_query response must not carry handle")
	}
	members, _ := q["sources"].([]any)
	if len(members) != 2 {
		t.Fatalf("multi-source hdf_query response sources = %v, want two members", q["sources"])
	}
	for i, m := range members {
		mm, _ := m.(map[string]any)
		if _, ok := mm["handle"]; ok {
			t.Errorf("sources[%d] must not carry a handle (a per-call token tax), got %v", i, mm)
		}
		if mm["source"] != []string{"sarif-gosec.json", "zap-webgoat.json"}[i] {
			t.Errorf("sources[%d].source = %v, want the member's path", i, mm["source"])
		}
	}

	c := callToolStructured(t, cs, "hdf_compliance", map[string]any{"sources": sources, "groupBy": "baseline"})
	if groups, _ := c["groups"].([]any); len(groups) != 5 {
		t.Errorf("hdf_compliance over the set: %d groups, want 5 (1 gosec + 4 ZAP sites)", len(groups))
	}

	// The exactly-one-of rule still holds, and it is the handler's argument
	// error — not a schema rejection — so its wording names both fields.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "hdf_query", Arguments: map[string]any{
		"source": map[string]any{"path": "zap-webgoat.json"}, "sources": sources, "limit": 1}})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	txt := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*sdkmcp.TextContent); ok {
			txt = tc.Text
		}
	}
	if !res.IsError || !strings.Contains(txt, "sets both source and sources") {
		t.Errorf("source+sources must be refused by the handler naming both fields, got isError=%v %s", res.IsError, txt)
	}
	// And a call with neither is the handler's error too, not the schema's.
	res, err = cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "hdf_query", Arguments: map[string]any{"limit": 1}})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	txt = ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*sdkmcp.TextContent); ok {
			txt = tc.Text
		}
	}
	if !res.IsError || strings.Contains(txt, "missing properties") || !strings.Contains(txt, "source sets neither path nor handle") {
		t.Errorf("a call with neither source nor sources must reach the handler's error, got isError=%v %s", res.IsError, txt)
	}
}
