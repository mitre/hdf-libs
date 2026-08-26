package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runGoList returns the transitive dependency list of this package via
// `go list -deps`, for the import-boundary assertion.
func runGoList(t *testing.T) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "list", "-deps", ".").CombinedOutput()
	return string(out), err
}

// serveOverPipes drives the server over an IOTransport using real pipes: the
// request writer stays open (so the session isn't torn down by a premature EOF),
// and the server's output is read concurrently. It writes the given request
// frames, then collects output until a JSON-RPC response for every id in
// wantIDs has arrived (or a short idle timeout), and returns the collected text.
func serveOverPipes(t *testing.T, requests string, wantIDs ...float64) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	transport := &mcp.IOTransport{Reader: reqR, Writer: respW}

	go func() {
		_ = NewServer("test-version", NewStderrLogger("error")).Run(ctx, transport)
		_ = respW.Close()
	}()

	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(respR)
		sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	if _, err := io.WriteString(reqW, requests); err != nil {
		t.Fatalf("write requests: %v", err)
	}

	want := map[float64]bool{}
	for _, id := range wantIDs {
		want[id] = true
	}
	var out bytes.Buffer
	idle := time.NewTimer(2 * time.Second)
	defer idle.Stop()
collect:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break collect
			}
			out.WriteString(line)
			out.WriteByte('\n')
			idle.Reset(500 * time.Millisecond)
			if id, done := seenResponseID(line); done {
				delete(want, id)
				if len(want) == 0 {
					break collect
				}
			}
		case <-idle.C:
			break collect
		}
	}
	_ = reqW.Close()
	cancel()
	return out.String()
}

// seenResponseID reports the id of a JSON-RPC response line (one carrying a
// result or error), or done=false for notifications and non-frames.
func seenResponseID(line string) (float64, bool) {
	var msg map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(line)), &msg) != nil {
		return 0, false
	}
	_, hasResult := msg["result"]
	_, hasError := msg["error"]
	if !hasResult && !hasError {
		return 0, false
	}
	id, ok := msg["id"].(float64)
	return id, ok
}

// initializeFrame builds a JSON-RPC initialize request for a specific protocol
// version — the way to exercise version negotiation without the SDK client's
// unexported version override.
func initializeFrame(protocolVersion string) string {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test-client", "version": "1.0.0"},
		},
	}
	b, _ := json.Marshal(req)
	return string(b) + "\n"
}

func TestStdoutOnlyJSONRPC(t *testing.T) {
	// Drive an initialize + tools/list over the transport; every line the server
	// writes must be a well-formed JSON-RPC frame (no stray prints).
	reqs := initializeFrame(latestNegotiated) +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"

	out := serveOverPipes(t, reqs, 2)
	if strings.TrimSpace(out) == "" {
		t.Fatal("server produced no output")
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	frames := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("non-JSON line on stdout (would corrupt JSON-RPC framing): %q", line)
		}
		if msg["jsonrpc"] != "2.0" {
			t.Errorf("frame missing jsonrpc:2.0: %q", line)
		}
		frames++
	}
	if frames == 0 {
		t.Fatal("no JSON-RPC frames written")
	}
}

func TestToolsListIsEmpty(t *testing.T) {
	reqs := initializeFrame(latestNegotiated) +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"

	out := serveOverPipes(t, reqs, 2)
	result := findResult(t, out, 2)
	tools, ok := result["tools"].([]any)
	if !ok {
		// tools omitempty → absent means empty; either is acceptable.
		if _, present := result["tools"]; present {
			t.Fatalf("tools field present but not an array: %v", result["tools"])
		}
		return
	}
	if len(tools) != 0 {
		t.Errorf("scaffold must expose an empty tool set, got %d tools", len(tools))
	}
}

func TestAdvertisesBothSpecRevisions(t *testing.T) {
	// The 2026-07-28 revision replaces the initialize handshake with a stateless
	// server/discover request (SEP-2575), whose response advertises the full
	// supported-version set. Drive discover and assert BOTH revisions are offered.
	// The stateless 2026-07-28 path is selected by the SEP-2575 per-request
	// _meta protocol-version key.
	discover := `{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"test-client","version":"1.0.0"}}}}` + "\n"
	out := serveOverPipes(t, discover, 3)
	res := findResult(t, out, 3)
	supported := toStringSet(res["supportedVersions"])
	for _, want := range []string{"2026-07-28", "2025-11-25"} {
		if !supported[want] {
			t.Errorf("server/discover supportedVersions %v does not advertise %q", res["supportedVersions"], want)
		}
	}

	// The legacy initialize path still negotiates the 2025-11-25 revision (the
	// newest the deprecated initialize method serves).
	iout := serveOverPipes(t, initializeFrame("2025-11-25"), 1)
	ires := findResult(t, iout, 1)
	if got, _ := ires["protocolVersion"].(string); got != "2025-11-25" {
		t.Errorf("initialize(2025-11-25): negotiated %q, want 2025-11-25", got)
	}
}

// modernRequestFrame builds a SEP-2575 stateless request: the protocol version
// travels in per-request `_meta` (not a prior initialize), so the server treats
// it as new-protocol and skips the initialization gate.
func modernRequestFrame(id float64, method, protocolVersion string) string {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params": map[string]any{
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    protocolVersion,
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "test-client", "version": "1.0.0"},
			},
		},
	}
	b, _ := json.Marshal(req)
	return string(b) + "\n"
}

// findError scans JSON-RPC output for the response with the given id and returns
// its error object, failing if that response is a success result instead.
func findError(t *testing.T, out string, id float64) map[string]any {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if json.Unmarshal([]byte(line), &msg) != nil {
			continue
		}
		if msg["id"] == id {
			errObj, isErr := msg["error"].(map[string]any)
			if !isErr {
				t.Fatalf("response id=%v is not an error: %v", id, msg)
			}
			return errObj
		}
	}
	t.Fatalf("no response with id=%v in output:\n%s", id, out)
	return nil
}

// TestUnsupportedProtocolVersion drives a SEP-2575 stateless request whose
// per-request `_meta` protocol version is one the server does not support, and
// asserts the negative path: JSON-RPC error -32022 (UnsupportedProtocolVersion)
// whose data advertises the supported versions so the client can renegotiate.
// The behavior is SDK-owned; this closes the conformance test-coverage gap.
func TestUnsupportedProtocolVersion(t *testing.T) {
	// A far-future version: lexically newer than 2026-07-28, so the SDK classifies
	// the request as new-protocol, yet not in the supported set — the -32022 path.
	// (An older unknown version is treated as legacy and never reaches this check.)
	out := serveOverPipes(t, modernRequestFrame(4, "server/discover", "2099-12-31"), 4)
	errObj := findError(t, out, 4)

	if code, _ := errObj["code"].(float64); code != -32022 {
		t.Errorf("error code = %v, want -32022 (UnsupportedProtocolVersion)", errObj["code"])
	}
	data, ok := errObj["data"].(map[string]any)
	if !ok {
		t.Fatalf("error missing data payload with supported versions: %v", errObj)
	}
	supported := toStringSet(data["supported"])
	for _, want := range []string{"2026-07-28", "2025-11-25"} {
		if !supported[want] {
			t.Errorf("error data supported=%v does not advertise %q", data["supported"], want)
		}
	}
}

// TestServerInfoInModernMeta covers the modern per-request identification path
// (SEP-2575): every new-protocol result carries the server implementation in its
// `_meta` under io.modelcontextprotocol/serverInfo. TestServerInfoCarriesVersion
// only checks the legacy initialize body; this asserts the modern path.
func TestServerInfoInModernMeta(t *testing.T) {
	out := serveOverPipes(t, modernRequestFrame(5, "tools/list", latestNegotiated), 5)
	res := findResult(t, out, 5)

	meta, ok := res["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("modern result missing _meta: %v", res)
	}
	info, ok := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("modern result _meta missing io.modelcontextprotocol/serverInfo: %v", meta)
	}
	if info["name"] != ServerName {
		t.Errorf("serverInfo.name = %v, want %s", info["name"], ServerName)
	}
	if info["version"] != "test-version" {
		t.Errorf("serverInfo.version = %v, want test-version (the real CLI version)", info["version"])
	}
}

func toStringSet(v any) map[string]bool {
	set := map[string]bool{}
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			if s, ok := e.(string); ok {
				set[s] = true
			}
		}
	}
	return set
}

func TestServerInfoCarriesVersion(t *testing.T) {
	out := serveOverPipes(t, initializeFrame(latestNegotiated), 1)
	res := findResult(t, out, 1)
	info, ok := res["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("initialize result missing serverInfo: %v", res)
	}
	if info["name"] != ServerName {
		t.Errorf("serverInfo.name = %v, want %s", info["name"], ServerName)
	}
	if info["version"] != "test-version" {
		t.Errorf("serverInfo.version = %v, want test-version", info["version"])
	}
}

// findResult scans JSON-RPC output for the response with the given id and
// returns its result object.
func findResult(t *testing.T, out string, id float64) map[string]any {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg["id"] == id {
			if errObj, isErr := msg["error"]; isErr {
				t.Fatalf("response id=%v is an error: %v", id, errObj)
			}
			res, ok := msg["result"].(map[string]any)
			if !ok {
				t.Fatalf("response id=%v has no result object: %v", id, msg)
			}
			return res
		}
	}
	t.Fatalf("no response with id=%v in output:\n%s", id, out)
	return nil
}

// latestNegotiated is the newest revision the SDK advertises; used where the
// test doesn't care which revision is negotiated.
const latestNegotiated = "2026-07-28"

func TestAnnotationHelpers(t *testing.T) {
	ro := ReadOnly()
	if !ro.ReadOnlyHint {
		t.Error("ReadOnly must set readOnlyHint=true")
	}
	if ro.DestructiveHint == nil || *ro.DestructiveHint {
		t.Error("ReadOnly must set destructiveHint=false")
	}
	if !ro.IdempotentHint {
		t.Error("ReadOnly must set idempotentHint=true")
	}
	if ro.OpenWorldHint == nil || *ro.OpenWorldHint {
		t.Error("ReadOnly must set openWorldHint=false")
	}

	w := Writing(false, false)
	if w.ReadOnlyHint {
		t.Error("Writing must set readOnlyHint=false")
	}
	if w.DestructiveHint == nil || *w.DestructiveHint {
		t.Error("Writing(false,..) must set destructiveHint=false (additive)")
	}
	wd := Writing(true, true)
	if wd.DestructiveHint == nil || !*wd.DestructiveHint || !wd.IdempotentHint {
		t.Error("Writing(true,true) must set destructiveHint=true, idempotentHint=true")
	}
}

func TestStderrLogger_LevelParsing(t *testing.T) {
	// A logger at error level must not emit info records; and it must never write
	// to the returned buffer as stdout (it targets stderr by construction). Here
	// we only assert level gating via a custom handler-equivalent check.
	cases := map[string]bool{"debug": true, "info": false, "warn": false, "error": false, "": false}
	for level, wantDebug := range cases {
		lg := NewStderrLogger(level)
		if lg.Enabled(context.Background(), -4) != wantDebug { // slog.LevelDebug == -4
			t.Errorf("level %q: debug enabled = %v, want %v", level, !wantDebug, wantDebug)
		}
	}
}

func TestNewServer_DefaultLogger(t *testing.T) {
	// A nil logger must fall back to the stderr logger (HDF_MCP_LOG_LEVEL) rather
	// than panic — the production wiring path.
	t.Setenv("HDF_MCP_LOG_LEVEL", "debug")
	s := NewServer("v", nil)
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestRun_StdioWiring(t *testing.T) {
	// Exercise Run's stdio wiring: redirect os.Stdin to an immediately-closed
	// pipe so the transport EOFs at once and Run returns without touching the real
	// terminal. This covers the production entry that serveOverPipes bypasses.
	origIn, origOut := os.Stdin, os.Stdout
	inR, inW, _ := os.Pipe()
	_, outW, _ := os.Pipe()
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = origIn, origOut }()
	_ = inW.Close() // EOF immediately

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = Run(ctx, "v", nil); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after stdin EOF")
	}
	_ = outW.Close()
}

// TestNoCobraImport asserts the internal/mcp package's import graph contains no
// cobra — the server logic must not depend on CLI command internals.
func TestNoCobraImport(t *testing.T) {
	out, err := runGoList(t)
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(out) {
		if strings.Contains(dep, "spf13/cobra") {
			t.Fatalf("internal/mcp must not import cobra, but its graph includes %q", dep)
		}
	}
}
