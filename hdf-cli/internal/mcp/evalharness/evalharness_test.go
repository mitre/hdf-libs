package evalharness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return string(b)
}

func readLines(t *testing.T, name string) []string {
	t.Helper()
	var out []string
	for _, ln := range strings.Split(readTestdata(t, name), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// realTranscript loads the recorded initialize+tools/list transcript captured
// from a real `hdf mcp` run.
func realTranscript(t *testing.T) Transcript {
	t.Helper()
	return Transcript{
		Name:        "initialize-toolslist",
		Requests:    readLines(t, "initialize-toolslist.requests.jsonl"),
		Responses:   readLines(t, "initialize-toolslist.responses.jsonl"),
		TokenBudget: 600, // generous; the recorded responses measure ~376 tokens
		Assert: func(responses []string) error {
			// Final answer: the tools/list response must advertise hdf_open.
			for _, r := range responses {
				var m map[string]any
				if json.Unmarshal([]byte(r), &m) != nil {
					continue
				}
				if m["id"] == float64(2) {
					res, _ := m["result"].(map[string]any)
					tools, _ := res["tools"].([]any)
					for _, tl := range tools {
						if tm, ok := tl.(map[string]any); ok && tm["name"] == "hdf_open" {
							return nil
						}
					}
					return fmt.Errorf("tools/list should advertise hdf_open, got %d tools", len(tools))
				}
			}
			return fmt.Errorf("no tools/list response found in transcript")
		},
	}
}

// The card's designated first-failing test: a transcript whose measured response
// token count grows past its declared budget fails the harness.
func TestHarness_FailsOnTokenRegression(t *testing.T) {
	tr := realTranscript(t)

	// A tiny budget forces a regression failure.
	tr.TokenBudget = 10
	res, err := Replay(tr)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res.Pass {
		t.Fatal("expected the transcript to FAIL its 10-token budget")
	}
	if !res.OverBudget || res.Overage <= 0 {
		t.Errorf("expected an over-budget report, got %+v", res)
	}

	// A generous budget passes and the final-answer assertion holds.
	tr.TokenBudget = 600
	res2, err := Replay(tr)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !res2.Pass {
		t.Fatalf("expected pass under a generous budget, got over=%v answerErr=%v total=%d", res2.OverBudget, res2.AnswerErr, res2.TotalTokens)
	}
}

func TestReplay_AssertsFinalAnswer(t *testing.T) {
	tr := realTranscript(t)
	// Break the assertion: demand a non-empty tools list the recording won't have.
	tr.Assert = func(responses []string) error { return fmt.Errorf("forced mismatch") }
	res, _ := Replay(tr)
	if res.Pass || res.AnswerErr == nil {
		t.Error("a failing final-answer assertion must fail the transcript even under budget")
	}
}

func TestTokenizerPinned(t *testing.T) {
	if !strings.Contains(PinnedEncoding, "o200k_base") {
		t.Errorf("pinned tokenizer name should record o200k_base, got %q", PinnedEncoding)
	}
	// Determinism: a fixed string must always tokenize to the same count.
	n1, err := CountTokens("hdf compliance rollup for RHEL9-STIG")
	if err != nil {
		t.Fatal(err)
	}
	n2, _ := CountTokens("hdf compliance rollup for RHEL9-STIG")
	if n1 != n2 || n1 == 0 {
		t.Errorf("tokenizer not deterministic/non-zero: %d vs %d", n1, n2)
	}
}

func TestMeasureToolsList_WithinCeilings(t *testing.T) {
	golden := readTestdata(t, "tools-list.golden.json")
	// Feed the real per-tool JSON so the per-tool ceiling (600) is enforced on the
	// production surface, not just the total — this is where tool-schema growth
	// surfaces before it silently consumes headroom.
	m, err := MeasureToolsList(golden, perToolJSON(t, golden))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Violations) != 0 {
		t.Errorf("golden tools/list must be within ceilings (total %d, per-tool %v), got violations: %v", m.TotalTokens, m.PerTool, m.Violations)
	}
	if m.TotalTokens > ToolsListTotalBudget {
		t.Errorf("golden tools/list %d tokens exceeds total budget %d", m.TotalTokens, ToolsListTotalBudget)
	}
}

// perToolJSON extracts each tool's own JSON object from a marshalled
// ListToolsResult, so the per-tool ceiling can be measured on the real surface.
func perToolJSON(t *testing.T, resultJSON string) map[string]string {
	t.Helper()
	var r struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &r); err != nil {
		t.Fatalf("parse tools/list: %v", err)
	}
	out := make(map[string]string, len(r.Tools))
	for _, raw := range r.Tools {
		var n struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(raw, &n)
		out[n.Name] = string(raw)
	}
	return out
}

func TestMeasureToolsList_FailsPastCeilings(t *testing.T) {
	// A per-tool schema over the per-tool ceiling is flagged. Varied words (not a
	// single repeated char, which BPE would collapse) so the token count is real.
	bigTool := `{"name":"hdf_query","description":"` + strings.Repeat("filter status severity impact cci nist ", 200) + `"}`
	m, err := MeasureToolsList(`{"tools":[]}`, map[string]string{"hdf_query": bigTool})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Violations) == 0 {
		t.Errorf("a large tool schema must breach the per-tool ceiling; per-tool measured %v", m.PerTool)
	}

	// A whole tools/list past the hard-fail ceiling is flagged.
	huge := `{"tools":["` + strings.Repeat("policy procedure technical management operational baseline requirement ", 1500) + `"]}`
	hm, _ := MeasureToolsList(huge, map[string]string{})
	hardFailed := false
	for _, v := range hm.Violations {
		if strings.Contains(v, "HARD-FAIL") {
			hardFailed = true
		}
	}
	if !hardFailed {
		t.Errorf("a tools/list past %d tokens must hard-fail, got %d tokens, violations %v", ToolsListHardFail, hm.TotalTokens, hm.Violations)
	}
}

func TestMeasureToolsList_OverBudgetNotHardFail(t *testing.T) {
	// A tools/list between the total budget and the hard-fail ceiling is flagged
	// as over-budget (but not hard-fail) — the middle branch.
	mid := `{"tools":["` + strings.Repeat("status severity impact requirement baseline component ", 800) + `"]}`
	m, _ := MeasureToolsList(mid, map[string]string{})
	if m.TotalTokens <= ToolsListTotalBudget || m.TotalTokens > ToolsListHardFail {
		t.Skipf("fixture sized %d not in the (%d, %d] over-budget band; adjust", m.TotalTokens, ToolsListTotalBudget, ToolsListHardFail)
	}
	overBudget, hardFail := false, false
	for _, v := range m.Violations {
		if strings.Contains(v, "over the total budget") {
			overBudget = true
		}
		if strings.Contains(v, "HARD-FAIL") {
			hardFail = true
		}
	}
	if !overBudget || hardFail {
		t.Errorf("expected an over-budget (non-hard-fail) violation, got %v", m.Violations)
	}
}

func TestTokenizerErrorPropagates(t *testing.T) {
	// Swap the token-counting seam to force an error, proving Replay and
	// MeasureToolsList propagate a tokenizer failure rather than swallowing it.
	orig := tokenCount
	tokenCount = func(string) (int, error) { return 0, fmt.Errorf("boom") }
	defer func() { tokenCount = orig }()

	if _, err := Replay(realTranscript(t)); err == nil {
		t.Error("Replay must propagate a tokenizer error")
	}
	if _, err := MeasureToolsList(`{"tools":[]}`, nil); err == nil {
		t.Error("MeasureToolsList must propagate a tokenizer error on the total")
	}
	if _, err := MeasureToolsList(`{}`, map[string]string{"t": "x"}); err == nil {
		t.Error("MeasureToolsList must propagate a tokenizer error on a per-tool count")
	}
}

func TestReplay_NilAssert(t *testing.T) {
	// A transcript with no Assert passes purely on the token budget.
	tr := realTranscript(t)
	tr.Assert = nil
	res, err := Replay(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pass || res.AnswerErr != nil {
		t.Errorf("nil Assert under budget must pass, got %+v", res)
	}
}

// TestToolsList_MatchesGolden re-drives the live server and asserts its
// tools/list equals the golden — so any growth in the tool surface surfaces in
// review rather than silently consuming headroom.
func TestToolsList_MatchesGolden(t *testing.T) {
	live := driveToolsList(t)
	golden := readTestdata(t, "tools-list.golden.json")

	if normalizeJSON(t, live) != normalizeJSON(t, golden) {
		t.Errorf("live tools/list differs from the golden — update the golden intentionally when the tool surface changes.\n live:   %s\n golden: %s", live, golden)
	}
}

// driveToolsList runs the real server in-process over a pipe transport and
// returns the tools/list result JSON (no shell-out to the hdf binary).
func driveToolsList(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		// Register the real tool set so the golden reflects the production surface
		// — the whole point of golden-filing it is that tool growth surfaces here.
		s := appmcp.NewServer("test-version", appmcp.NewStderrLogger("error"))
		tools.RegisterAll(s)
		_ = s.Run(ctx, &sdkmcp.IOTransport{Reader: reqR, Writer: respW})
		_ = respW.Close()
	}()

	reqs := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"eval","version":"1.0.0"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	go func() { _, _ = io.WriteString(reqW, reqs) }()

	sc := bufio.NewScanner(respR)
	sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	deadline := time.After(4 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for tools/list response")
		default:
		}
		if !sc.Scan() {
			t.Fatal("server closed before tools/list response")
		}
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if m["id"] == float64(2) {
			res := m["result"]
			b, _ := json.Marshal(res)
			_ = reqW.Close()
			cancel()
			return string(b)
		}
	}
}

// TestToolsList_NoBareBooleanSchemas guards against schemas MCP clients reject:
// a bare JSON boolean (true/false) under an `items` or `properties.<k>` position.
// It is valid JSON Schema but Claude Code's zod validator rejects it, failing the
// whole tools/list. additionalProperties: true is fine (and excluded here).
func TestToolsList_NoBareBooleanSchemas(t *testing.T) {
	var r struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal([]byte(driveToolsList(t)), &r); err != nil {
		t.Fatalf("parse tools/list: %v", err)
	}
	var hits []string
	for _, tool := range r.Tools {
		name, _ := tool["name"].(string)
		for _, key := range []string{"inputSchema", "outputSchema"} {
			hits = append(hits, bareBooleanSchemas(tool[key], name+"."+key)...)
		}
	}
	if len(hits) > 0 {
		t.Errorf("tools/list must not expose bare boolean schemas under items/properties (MCP clients reject them):\n  %s",
			strings.Join(hits, "\n  "))
	}
}

// bareBooleanSchemas walks a schema and reports every `items` or `properties.<k>`
// whose value is a JSON boolean. additionalProperties booleans are allowed.
func bareBooleanSchemas(node any, path string) []string {
	var hits []string
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			switch k {
			case "items":
				if _, ok := v.(bool); ok {
					hits = append(hits, path+".items")
				}
			case "properties":
				if props, ok := v.(map[string]any); ok {
					for pk, pv := range props {
						if _, ok := pv.(bool); ok {
							hits = append(hits, path+".properties."+pk)
						}
					}
				}
			}
			hits = append(hits, bareBooleanSchemas(v, path+"."+k)...)
		}
	case []any:
		for i, x := range n {
			hits = append(hits, bareBooleanSchemas(x, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return hits
}

func normalizeJSON(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("normalize: invalid JSON %q: %v", s, err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(buf.String())
}
