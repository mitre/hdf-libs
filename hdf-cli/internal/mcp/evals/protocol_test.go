package evals

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/resources"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// serveRaw sends raw JSON-RPC frames to the in-process server and returns the
// result object for the given id. Unlike driveCalls it does not perform the
// initialize handshake itself — the caller supplies the exact frames, so it can
// exercise version negotiation.
func serveRaw(t *testing.T, frames string, wantID int) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	go func() { _, _ = io.WriteString(reqW, frames) }()
	sc := bufio.NewScanner(respR)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			t.Fatalf("non-JSON-RPC line on stdout: %q", line)
		}
		if idf, ok := m["id"].(float64); ok && int(idf) == wantID {
			cancel()
			res, _ := m["result"].(map[string]any)
			return res
		}
	}
	t.Fatalf("no response for id %d", wantID)
	return nil
}

// TestProtocol_BothSpecRevisionsNegotiate — the legacy initialize path
// negotiates 2025-11-25, and the stateless server/discover (SEP-2575) advertises
// both 2026-07-28 and 2025-11-25 (§14/§17).
func TestProtocol_BothSpecRevisionsNegotiate(t *testing.T) {
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"eval","version":"1"}}}` + "\n"
	ires := serveRaw(t, init, 1)
	if got, _ := ires["protocolVersion"].(string); got != "2025-11-25" {
		t.Errorf("initialize negotiated %q, want 2025-11-25", got)
	}

	discover := `{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"eval","version":"1"}}}}` + "\n"
	dres := serveRaw(t, discover, 3)
	supported := map[string]bool{}
	if arr, ok := dres["supportedVersions"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				supported[s] = true
			}
		}
	}
	for _, want := range []string{"2026-07-28", "2025-11-25"} {
		if !supported[want] {
			t.Errorf("server/discover does not advertise %q (got %v)", want, dres["supportedVersions"])
		}
	}
}

// TestProtocol_StdoutOnlyJSONRPC — a driven tool call produces only JSON-RPC
// frames on stdout. driveCalls fatals on any non-JSON-RPC line, so a successful
// drive IS the assertion.
func TestProtocol_StdoutOnlyJSONRPC(t *testing.T) {
	stageRoot(t, [2]string{fxSystem, "system.json"})
	resp := driveCalls(t, []call{{"hdf_inspect", map[string]any{"source": map[string]any{"path": "system.json"}}}})
	if len(resp) != 1 || resp[0] == "" {
		t.Fatal("expected exactly one JSON-RPC response frame")
	}
}

// TestProtocol_PerToolTimingUnderThreshold — each read tool handles the 5 MB
// hdf-fixtures/inspec/wrapper.json well under the §16 10 s threshold. Timings are
// logged; any tool over threshold is flagged (§16).
func TestProtocol_PerToolTimingUnderThreshold(t *testing.T) {
	stageRoot(t, [2]string{fxBigScan, "big.json"})
	const threshold = 10 * time.Second
	src := map[string]any{"path": "big.json"}
	readTools := []call{
		{"hdf_open", map[string]any{"source": src}},
		{"hdf_inspect", map[string]any{"source": src}},
		{"hdf_query", map[string]any{"source": src, "status": []any{"failed"}}},
		{"hdf_compliance", map[string]any{"source": src}},
	}
	for _, c := range readTools {
		start := time.Now()
		driveCalls(t, []call{c})
		elapsed := time.Since(start)
		t.Logf("§16 timing: %-16s %v (threshold %v)", c.Tool, elapsed.Round(time.Millisecond), threshold)
		if elapsed > threshold {
			t.Errorf("%s took %v, over the §16 %v threshold", c.Tool, elapsed, threshold)
		}
	}
}
