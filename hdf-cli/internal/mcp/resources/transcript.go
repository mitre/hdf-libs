package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The transcript exposes what an agent has done THIS stdio session as a
// read-only MCP resource, so a client (or a human debugging the agent) can read
// its own tool-call history back without scraping the server's stderr logs. It
// is deliberately narrow (external reference: the MITRE Caldera MCP plugin's run
// transcript, github.com/mitre/mcp): per-session and in-memory only — a new
// stdio session starts empty and nothing is written to disk — bounded, and free
// of any wall-clock. Ordering is a monotonic call ordinal, never a timestamp, so
// nothing here can pull a wall-clock into a tool RESPONSE payload (ADR-0007 §12).
const (
	// transcriptCap bounds the in-memory history; beyond it the oldest entries
	// are dropped and counted (no unbounded growth over a long session).
	transcriptCap = 200
	// argSummaryCap bounds the per-call argument summary length.
	argSummaryCap = 200
	// argValueCap bounds each individual scalar argument value.
	argValueCap = 40

	transcriptURI = "hdf://session/transcript"
)

// transcriptEntry is one recorded tool call. It carries an ordinal (call order),
// never a wall-clock timestamp.
type transcriptEntry struct {
	Ordinal int    `json:"ordinal"`
	Tool    string `json:"tool"`
	Args    string `json:"args,omitempty"`
	Outcome string `json:"outcome"`
}

// Transcript is a per-session, in-memory, bounded record of tool calls. It is
// created per server (== per stdio session) and is safe for concurrent tool
// dispatch within a session.
type Transcript struct {
	mu      sync.Mutex
	entries []transcriptEntry
	ordinal int // total calls seen, including dropped — also the ordinal source
	dropped int
	cap     int
}

func newTranscript(capN int) *Transcript { return &Transcript{cap: capN} }

// RegisterTranscript installs the per-session tool-call transcript on the server:
// it creates one Transcript (scoped to this server == this stdio session),
// registers the recording middleware once (the single central recording site),
// and exposes the read-only transcript resource. Called from RegisterAll so every
// deployment — production and the eval harness — gets it wired identically.
func RegisterTranscript(s *sdkmcp.Server) {
	tr := newTranscript(transcriptCap)
	s.AddReceivingMiddleware(tr.middleware())
	s.AddResource(&sdkmcp.Resource{
		Name:        "hdf-session-transcript",
		Title:       "HDF session tool-call transcript",
		URI:         transcriptURI,
		MIMEType:    "application/json",
		Description: "This stdio session's ordered tool-call transcript: per call an ordinal (call order, NOT a wall-clock timestamp), the tool name, a bounded redacted argument summary (nested values elided, absolute paths removed), and the outcome (\"ok\" or \"error:<CODE>\"). In-memory and per-session — a new session starts empty and nothing is written to disk; capped at 200 entries (oldest dropped, with a dropped count).",
	}, tr.handleRead)
}

// record appends one tool call, assigning the next ordinal and dropping the
// oldest entries past the cap (their count accumulates in dropped).
func (tr *Transcript) record(tool, args, outcome string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.ordinal++
	tr.entries = append(tr.entries, transcriptEntry{Ordinal: tr.ordinal, Tool: tool, Args: args, Outcome: outcome})
	if over := len(tr.entries) - tr.cap; over > 0 {
		tr.entries = tr.entries[over:]
		tr.dropped += over
	}
}

// snapshot returns a copy of the retained entries plus the total-calls and
// dropped counts, so callers never hold a reference to mutable internal state.
func (tr *Transcript) snapshot() (entries []transcriptEntry, total, dropped int) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	out := make([]transcriptEntry, len(tr.entries))
	copy(out, tr.entries)
	return out, tr.ordinal, tr.dropped
}

// middleware records every tools/call into the transcript. It is the single,
// central recording site (no per-tool-handler duplication): it reads the tool
// name and a redacted argument summary from the request, delegates to the real
// handler, and records the outcome. It passes the result through unchanged, so
// no tool response is altered and no wall-clock is introduced.
func (tr *Transcript) middleware() sdkmcp.Middleware {
	return func(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
		return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			tool, args := "", ""
			if p, ok := req.GetParams().(*sdkmcp.CallToolParamsRaw); ok && p != nil {
				tool = p.Name
				args = summarizeArgs(p.Arguments)
			}
			res, err := next(ctx, method, req)
			tr.record(tool, args, outcomeOf(res, err))
			return res, err
		}
	}
}

// handleRead serves the transcript resource: the ordered retained calls plus the
// total and (when the cap has dropped any) a dropped count and notice.
func (tr *Transcript) handleRead(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	entries, total, dropped := tr.snapshot()
	payload := map[string]any{
		"calls":      entries,
		"count":      len(entries),
		"totalCalls": total,
	}
	if dropped > 0 {
		payload["dropped"] = dropped
		payload["notice"] = fmt.Sprintf("transcript capped at %d entries; %d earliest dropped", tr.cap, dropped)
	}
	uri := transcriptURI
	if req != nil && req.Params != nil && req.Params.URI != "" {
		uri = req.Params.URI
	}
	return jsonResource(uri, payload)
}

// outcomeOf classifies a tool-call result: "ok" for a success, "error:<CODE>"
// when the error result carries a taxonomy code, or "error" for a code-less
// caller-arg error or a transport error.
func outcomeOf(res sdkmcp.Result, err error) string {
	if err != nil {
		return "error"
	}
	ct, ok := res.(*sdkmcp.CallToolResult)
	if !ok || ct == nil || !ct.IsError {
		return "ok"
	}
	if code := errorCode(ct); code != "" {
		return "error:" + code
	}
	return "error"
}

// errorCode extracts the taxonomy code from an error result's JSON text content
// (mcperr renders {..,"code":..}; a code-less arg error has none).
func errorCode(ct *sdkmcp.CallToolResult) string {
	for _, c := range ct.Content {
		tc, ok := c.(*sdkmcp.TextContent)
		if !ok {
			continue
		}
		var body struct {
			Code string `json:"code"`
		}
		if json.Unmarshal([]byte(tc.Text), &body) == nil && body.Code != "" {
			return body.Code
		}
	}
	return ""
}

// summarizeArgs renders a bounded, leak-safe summary of a tool call's arguments:
// top-level keys sorted, scalar values inlined (absolute paths redacted, each
// value length-capped), and nested objects/arrays elided to {…}/[…] so no nested
// value (a path, a reason string) is ever surfaced. The whole summary is capped.
func summarizeArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+summarizeValue(m[k]))
	}
	return capString(strings.Join(parts, ", "), argSummaryCap)
}

// summarizeValue renders one argument value: nested objects/arrays are elided,
// strings are quoted with absolute paths redacted and length-capped, and other
// scalars are rendered raw (also capped).
func summarizeValue(raw json.RawMessage) string {
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return ""
	}
	switch v[0] {
	case '{':
		return "{…}"
	case '[':
		return "[…]"
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return `"…"`
		}
		return `"` + capString(redactPath(s), argValueCap) + `"`
	default:
		return capString(v, argValueCap)
	}
}

// absPathToken matches an absolute-path token (unix, UNC, or Windows drive) at a
// string boundary — used to scrub a path embedded inside a larger scalar value.
var absPathToken = regexp.MustCompile(`(^|\s)(/\S+|\\\\\S+|[A-Za-z]:[\\/]\S+)`)

// redactPath removes absolute filesystem paths from a scalar argument value so
// the transcript never surfaces the deployer's HDF_MCP_ROOT layout — relative
// paths (the confined tool inputs) are kept. A whole-value path collapses to
// "<path>"; an embedded path token is scrubbed in place (defense-in-depth, since
// summarizeValue already elides nested objects/arrays where paths usually live).
func redactPath(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, `\\`) || isWindowsDrivePath(t) {
		return "<path>"
	}
	return absPathToken.ReplaceAllString(s, "$1<path>")
}

func isWindowsDrivePath(s string) bool {
	return len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') &&
		((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'))
}

// capString truncates s to n runes, appending an ellipsis when it was longer.
func capString(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
