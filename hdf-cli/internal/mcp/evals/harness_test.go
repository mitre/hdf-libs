// Package evals is the executable verification suite for the HDF MCP server: the
// six target evals as driven tool-call transcripts (answer + token-budget
// assertions), plus the write-gate, agent-attribution, determinism, protocol,
// TOON, and golden-response tests. It drives the REAL in-process server (never
// shelling out) and reuses the server's own tool handlers — it never
// re-implements tool behaviour.
package evals

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/evalharness"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/resources"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// call is one tool call in a transcript: the tool name and its arguments.
type call struct {
	Tool string
	Args map[string]any
}

// callFrame renders a tools/call JSON-RPC request frame with the given id.
func callFrame(id int, c call) string {
	params := map[string]any{"name": c.Tool, "arguments": c.Args}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
	return string(b)
}

// driveCalls runs the REAL in-process server (tools + resources, exactly the
// production registration) over a pipe transport, sends initialize + initialized
// + one tools/call per call, and returns the raw response frame for each call in
// order. It asserts stdout carries only JSON-RPC frames (every line parses as a
// JSON-RPC message). The responses ARE the recording the eval measures and
// asserts against — no shelling out, no re-implementation.
func driveCalls(t *testing.T, calls []call) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		s := appmcp.NewServer("test-version", appmcp.NewStderrLogger("error"))
		tools.RegisterAll(s)
		resources.RegisterAll(s)
		_ = s.Run(ctx, &sdkmcp.IOTransport{Reader: reqR, Writer: respW})
		_ = respW.Close()
	}()

	var b strings.Builder
	b.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"eval","version":"1.0.0"}}}` + "\n")
	b.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	for i, c := range calls {
		b.WriteString(callFrame(i+2, c) + "\n") // ids 2..N+1
	}
	// Keep the request pipe open — closing it EOFs the server before it
	// responds. cancel() (on receiving the last response, or the deadline) tears
	// the session down.
	go func() { _, _ = io.WriteString(reqW, b.String()) }()

	byID := map[int]string{}
	sc := bufio.NewScanner(respR)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	lastID := len(calls) + 1
	deadline := time.After(12 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for tool-call responses (%d/%d)", len(byID), len(calls))
		default:
		}
		if !sc.Scan() {
			t.Fatalf("server closed before all responses (%d/%d)", len(byID), len(calls))
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout carried a non-JSON-RPC line (protocol violation): %q", line)
		}
		if m["jsonrpc"] != "2.0" {
			t.Fatalf("stdout line is not a JSON-RPC 2.0 frame: %q", line)
		}
		idf, ok := m["id"].(float64)
		if !ok {
			continue // a notification or log frame — no id
		}
		id := int(idf)
		if id >= 2 && id <= lastID {
			byID[id] = line
		}
		// Responses can arrive out of order — wait for every call's response.
		if len(byID) == len(calls) {
			cancel()
			out := make([]string, len(calls))
			for i := range calls {
				out[i] = byID[i+2]
			}
			return out
		}
	}
}

// structured extracts the structuredContent object from a tools/call response
// frame. Fails the test if the call returned an isError result.
func structured(t *testing.T, responseFrame string) map[string]any {
	t.Helper()
	var m struct {
		Result struct {
			StructuredContent map[string]any `json:"structuredContent"`
			IsError           bool           `json:"isError"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(responseFrame), &m); err != nil {
		t.Fatalf("parse response frame: %v\n%s", err, responseFrame)
	}
	if m.Result.IsError {
		txt := ""
		if len(m.Result.Content) > 0 {
			txt = m.Result.Content[0].Text
		}
		t.Fatalf("tool returned an error result: %s", txt)
	}
	return m.Result.StructuredContent
}

// runTranscript builds an evalharness.Transcript from the live responses and
// replays it: it enforces the per-transcript token budget AND the final-answer
// assertion. A transcript with no budget (0) is a card violation, not an eval.
func runTranscript(t *testing.T, name string, calls []call, budget int, assert func(responses []string) error) evalharness.Result {
	t.Helper()
	return replayResponses(t, name, driveCalls(t, calls), budget, assert)
}

// replayResponses enforces the per-transcript token budget AND the final-answer
// assertion over already-collected response frames. Multi-stage evals (which
// must barrier between stages — e.g. author-writes-a-file then apply-reads-it)
// drive each stage with its own driveCalls and combine the responses here.
func replayResponses(t *testing.T, name string, responses []string, budget int, assert func(responses []string) error) evalharness.Result {
	t.Helper()
	if budget <= 0 {
		t.Fatalf("eval %q has no token budget — every one of the six evals asserts a budget", name)
	}
	res, err := evalharness.Replay(evalharness.Transcript{
		Name:        name,
		Responses:   responses,
		TokenBudget: budget,
		Assert:      assert,
	})
	if err != nil {
		t.Fatalf("replay %q: %v", name, err)
	}
	if !res.Pass {
		t.Fatalf("eval %q failed: overBudget=%v (tokens=%d budget=%d) answerErr=%v",
			name, res.OverBudget, res.TotalTokens, res.Budget, res.AnswerErr)
	}
	return res
}

// jointext concatenates response frames for substring answer assertions.
func jointext(responses []string) string { return strings.Join(responses, "\n") }

// answerContains asserts every wanted substring appears somewhere in the
// transcript's responses (the derived "final answer" an agent would give).
func answerContains(responses []string, want ...string) error {
	joined := jointext(responses)
	for _, w := range want {
		if !strings.Contains(joined, w) {
			return fmt.Errorf("answer missing %q", w)
		}
	}
	return nil
}
