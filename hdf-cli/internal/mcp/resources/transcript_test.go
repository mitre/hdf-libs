package resources

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestTranscript_RecordSnapshotOrder(t *testing.T) {
	tr := newTranscript(200)
	tr.record("hdf_open", "source={…}", "ok")
	tr.record("hdf_query", `impact=">0.5"`, "error:DOCUMENT_NOT_FOUND")
	entries, total, dropped := tr.snapshot()
	if total != 2 || dropped != 0 || len(entries) != 2 {
		t.Fatalf("total=%d dropped=%d len=%d", total, dropped, len(entries))
	}
	if entries[0].Ordinal != 1 || entries[0].Tool != "hdf_open" || entries[0].Outcome != "ok" {
		t.Fatalf("entry0 = %+v", entries[0])
	}
	if entries[1].Ordinal != 2 || entries[1].Tool != "hdf_query" || entries[1].Outcome != "error:DOCUMENT_NOT_FOUND" {
		t.Fatalf("entry1 = %+v", entries[1])
	}
}

func TestTranscript_BoundedOldestDropped(t *testing.T) {
	tr := newTranscript(3)
	for i := 0; i < 5; i++ {
		tr.record("t", "", "ok")
	}
	entries, total, dropped := tr.snapshot()
	if len(entries) != 3 {
		t.Fatalf("len=%d, want 3 (cap)", len(entries))
	}
	if total != 5 {
		t.Fatalf("total=%d, want 5 (ordinal counts all calls, dropped or not)", total)
	}
	if dropped != 2 {
		t.Fatalf("dropped=%d, want 2", dropped)
	}
	// Oldest dropped: the retained window is the last 3 ordinals (3,4,5).
	if entries[0].Ordinal != 3 || entries[2].Ordinal != 5 {
		t.Fatalf("not oldest-dropped: retained %d..%d", entries[0].Ordinal, entries[2].Ordinal)
	}
}

func TestTranscript_SnapshotIsCopy(t *testing.T) {
	tr := newTranscript(10)
	tr.record("a", "", "ok")
	entries, _, _ := tr.snapshot()
	entries[0].Tool = "MUTATED"
	again, _, _ := tr.snapshot()
	if again[0].Tool != "a" {
		t.Fatal("snapshot must return a copy; internal state was mutated through it")
	}
}

func TestSummarizeArgs_RedactsAndElides(t *testing.T) {
	raw := json.RawMessage(`{"source":{"path":"r.json"},"status":["failed"],"impact":">0.5","output":"/etc/secret","docType":"amendments"}`)
	s := summarizeArgs(raw)
	if !strings.Contains(s, "source={…}") {
		t.Errorf("nested object not elided: %q", s)
	}
	if !strings.Contains(s, "status=[…]") {
		t.Errorf("nested array not elided: %q", s)
	}
	if !strings.Contains(s, `impact=">0.5"`) {
		t.Errorf("scalar impact missing: %q", s)
	}
	if !strings.Contains(s, `docType="amendments"`) {
		t.Errorf("scalar docType missing: %q", s)
	}
	if strings.Contains(s, "/etc/secret") {
		t.Errorf("absolute path leaked into summary: %q", s)
	}
	if !strings.Contains(s, `output="<path>"`) {
		t.Errorf("absolute path not redacted: %q", s)
	}
	// Keys are sorted for a stable summary.
	if strings.Index(s, "docType") >= strings.Index(s, "impact") || strings.Index(s, "impact") >= strings.Index(s, "output") {
		t.Errorf("keys not sorted: %q", s)
	}
}

func TestSummarizeArgs_Cap(t *testing.T) {
	raw := json.RawMessage(`{"name":"` + strings.Repeat("x", 500) + `"}`)
	s := summarizeArgs(raw)
	if len(s) > argSummaryCap+len("…") {
		t.Errorf("summary not capped: len=%d cap=%d", len(s), argSummaryCap)
	}
}

func TestRedactPath(t *testing.T) {
	cases := map[string]string{
		"r.json":               "r.json",              // relative — kept
		"amendments.json":      "amendments.json",     // relative — kept
		">0.5":                 ">0.5",                // not a path — kept
		"/etc/secret":          "<path>",              // whole-value unix abs
		`C:\Users\x\a.json`:    "<path>",              // whole-value windows drive
		`\\host\share\x`:       "<path>",              // whole-value UNC
		"see /etc/x here":      "see <path> here",     // embedded unix abs scrubbed
		"a /root/b and /var/c": "a <path> and <path>", // multiple embedded
	}
	for in, want := range cases {
		if got := redactPath(in); got != want {
			t.Errorf("redactPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarizeArgs_Empty(t *testing.T) {
	if summarizeArgs(nil) != "" {
		t.Error("nil args must summarize to empty")
	}
	if summarizeArgs(json.RawMessage(`not json`)) != "" {
		t.Error("unparseable args must summarize to empty, not panic")
	}
}

type fakeError struct{}

func (fakeError) Error() string { return "transport" }

func TestOutcomeOf(t *testing.T) {
	if got := outcomeOf(&sdkmcp.CallToolResult{IsError: false}, nil); got != "ok" {
		t.Errorf("success outcome = %q, want ok", got)
	}
	if got := outcomeOf(nil, fakeError{}); got != "error" {
		t.Errorf("transport-error outcome = %q, want error", got)
	}
	coded := &sdkmcp.CallToolResult{IsError: true, Content: []sdkmcp.Content{
		&sdkmcp.TextContent{Text: `{"isError":true,"code":"DOCUMENT_NOT_FOUND","nextCall":"x"}`}}}
	if got := outcomeOf(coded, nil); got != "error:DOCUMENT_NOT_FOUND" {
		t.Errorf("coded-error outcome = %q, want error:DOCUMENT_NOT_FOUND", got)
	}
	argErr := &sdkmcp.CallToolResult{IsError: true, Content: []sdkmcp.Content{
		&sdkmcp.TextContent{Text: `{"error":"both source and content","nextCall":"x"}`}}}
	if got := outcomeOf(argErr, nil); got != "error" {
		t.Errorf("code-less arg-error outcome = %q, want error", got)
	}
}

func TestTranscript_HandleRead_EmptyThenPopulated(t *testing.T) {
	tr := newTranscript(200)
	res, err := tr.handleRead(context.Background(), readReq("hdf://session/transcript"))
	if err != nil {
		t.Fatal(err)
	}
	var empty map[string]any
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &empty); err != nil {
		t.Fatal(err)
	}
	if empty["count"].(float64) != 0 {
		t.Errorf("fresh transcript must be empty: %v", empty)
	}
	if _, ok := empty["calls"].([]any); !ok {
		t.Errorf("calls must serialize as an array (not null): %v", empty["calls"])
	}

	tr.record("hdf_open", "source={…}", "ok")
	res2, _ := tr.handleRead(context.Background(), readReq("hdf://session/transcript"))
	var pop map[string]any
	if err := json.Unmarshal([]byte(res2.Contents[0].Text), &pop); err != nil {
		t.Fatal(err)
	}
	if pop["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", pop["count"])
	}
	c0 := pop["calls"].([]any)[0].(map[string]any)
	if c0["tool"] != "hdf_open" || c0["ordinal"].(float64) != 1 || c0["outcome"] != "ok" {
		t.Errorf("entry = %v", c0)
	}
}
