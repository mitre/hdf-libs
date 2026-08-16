package evals

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/resources"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectSession stands up the REAL in-process server (tools + resources + the
// transcript middleware, exactly the production registration) and returns a
// connected in-memory client session. Each call is a fresh server == a fresh
// stdio session.
func connectSession(t *testing.T) *sdkmcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	s := appmcp.NewServer("test-version", appmcp.NewStderrLogger("error"))
	tools.RegisterAll(s)
	resources.RegisterAll(s)
	clientT, serverT := sdkmcp.NewInMemoryTransports()
	if _, err := s.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	c := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "eval", Version: "1.0.0"}, nil)
	cs, err := c.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func readTranscript(t *testing.T, cs *sdkmcp.ClientSession) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: "hdf://session/transcript"})
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &payload); err != nil {
		t.Fatalf("parse transcript: %v", err)
	}
	return payload
}

// TestTranscript_EndToEndOrderedRecord drives a multi-call session through the
// real server and asserts the transcript resource returns the calls in order
// with their outcomes — proving the middleware records every tool call once,
// centrally, and the resource reads it back (bead 4908.22).
func TestTranscript_EndToEndOrderedRecord(t *testing.T) {
	root := stageRoot(t, [2]string{fxAgentOverrides, "r.json"})
	_ = root
	cs := connectSession(t)
	ctx := context.Background()

	// A fresh session starts empty.
	if p := readTranscript(t, cs); p["count"].(float64) != 0 {
		t.Fatalf("fresh session transcript must be empty, got %v", p)
	}

	// One successful call, then one that errors (missing document).
	if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "hdf_compliance", Arguments: map[string]any{"source": map[string]any{"path": "r.json"}},
	}); err != nil {
		t.Fatalf("compliance call: %v", err)
	}
	if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "hdf_open", Arguments: map[string]any{"source": map[string]any{"path": "does-not-exist.json"}},
	}); err != nil {
		t.Fatalf("open call transport error: %v", err) // an isError RESULT is not a transport error
	}

	p := readTranscript(t, cs)
	if p["count"].(float64) != 2 || p["totalCalls"].(float64) != 2 {
		t.Fatalf("want 2 recorded calls, got count=%v total=%v", p["count"], p["totalCalls"])
	}
	calls := p["calls"].([]any)
	first := calls[0].(map[string]any)
	second := calls[1].(map[string]any)
	if first["ordinal"].(float64) != 1 || first["tool"] != "hdf_compliance" || first["outcome"] != "ok" {
		t.Errorf("first entry = %v, want ordinal 1 / hdf_compliance / ok", first)
	}
	if second["ordinal"].(float64) != 2 || second["tool"] != "hdf_open" {
		t.Errorf("second entry = %v, want ordinal 2 / hdf_open", second)
	}
	if oc, _ := second["outcome"].(string); !strings.HasPrefix(oc, "error") {
		t.Errorf("second outcome = %q, want an error outcome", oc)
	}
	// The recorded args must not leak the absolute staged path.
	if a, _ := second["args"].(string); strings.Contains(a, root) {
		t.Errorf("transcript arg summary leaked the absolute root: %q", a)
	}
}

// TestTranscript_PerSessionIsolation confirms the transcript does not persist
// across sessions: a second, independent session starts empty even after the
// first recorded calls.
func TestTranscript_PerSessionIsolation(t *testing.T) {
	stageRoot(t, [2]string{fxAgentOverrides, "r.json"})
	ctx := context.Background()

	cs1 := connectSession(t)
	if _, err := cs1.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "hdf_compliance", Arguments: map[string]any{"source": map[string]any{"path": "r.json"}},
	}); err != nil {
		t.Fatal(err)
	}
	if p := readTranscript(t, cs1); p["count"].(float64) != 1 {
		t.Fatalf("session 1 should have 1 call, got %v", p["count"])
	}

	cs2 := connectSession(t)
	if p := readTranscript(t, cs2); p["count"].(float64) != 0 {
		t.Fatalf("session 2 must start empty (no cross-session state), got %v", p["count"])
	}
}
