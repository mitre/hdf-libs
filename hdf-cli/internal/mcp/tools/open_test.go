package tools

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeRoot writes content into a fresh HDF_MCP_ROOT temp dir and returns the
// base filename to pass as source.path.
func writeRoot(t *testing.T, name string, content []byte) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return name
}

func callOpen(t *testing.T, in openInput) (*sdkmcp.CallToolResult, openOutput) {
	t.Helper()
	res, out, err := hdfOpen(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfOpen returned a Go error (should use degraded/taxonomy paths): %v", err)
	}
	return res, out
}

// The card's designated first-failing test.
func TestHdfOpen_MintsHandle_AndTypeSpecificSummary(t *testing.T) {
	content := fixtures.Results.Minimal
	path := writeRoot(t, "scan.json", content)

	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if errRes != nil {
		t.Fatalf("valid results should not be an error result: %+v", errRes)
	}
	if !out.Valid {
		t.Fatalf("expected valid=true, got errors: %+v", out.ValidationErrors)
	}
	if out.DocType != "results" {
		t.Errorf("docType = %q, want results", out.DocType)
	}

	// Handle round-trips through the codec to the identical struct...
	h, err := handle.Decode(out.Handle)
	if err != nil {
		t.Fatalf("handle does not decode: %v", err)
	}
	if h.Path != path || h.DocType != "results" || h.EngineSchemaVersion == "" || h.ContentSHA256 == "" || h.Size != int64(len(content)) {
		t.Errorf("handle identity fields wrong: %+v", h)
	}
	// The field records the validating engine's schema version (HDF documents
	// do not self-declare one), sourced from hdfengine.Version() — decided in
	// w913.29.
	if h.EngineSchemaVersion != hdfengine.Version() {
		t.Errorf("engineSchemaVersion = %q, want the engine version %q", h.EngineSchemaVersion, hdfengine.Version())
	}
	// ...and passes the staleness check against the same file.
	if verr := handle.Verify(h, content); verr != nil {
		t.Errorf("fresh handle should verify against the file: %v", verr)
	}

	// Results-shaped summary: baseline count, requirement count, status breakdown.
	if out.Summary == nil {
		t.Fatal("valid results must carry a summary")
	}
	if _, ok := out.Summary["baselineCount"]; !ok {
		t.Error("summary missing baselineCount")
	}
	if rc, ok := out.Summary["requirementCount"].(int); !ok || rc <= 0 {
		t.Errorf("summary requirementCount should be a positive int, got %v", out.Summary["requirementCount"])
	}
	sb, ok := out.Summary["statusBreakdown"].(map[string]int)
	if !ok {
		t.Fatalf("summary statusBreakdown should be a map[string]int, got %T", out.Summary["statusBreakdown"])
	}
	for _, k := range []string{"passed", "failed", "notApplicable", "notReviewed", "error"} {
		if _, ok := sb[k]; !ok {
			t.Errorf("statusBreakdown missing key %q", k)
		}
	}
}

func TestHdfOpen_SystemSummary(t *testing.T) {
	content := readCLIFixture(t, "system.json")
	path := writeRoot(t, "system.json", content)
	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if errRes != nil || !out.Valid {
		t.Fatalf("valid system doc must open valid: err=%v out=%+v", errRes, out)
	}
	if out.DocType != "system" {
		t.Errorf("docType = %q, want system", out.DocType)
	}
	if out.Summary == nil || out.Summary["componentCount"] == nil || out.Summary["componentByType"] == nil {
		t.Errorf("system summary must carry component count by type, got %+v", out.Summary)
	}
}

func TestHdfOpen_PlanSummary(t *testing.T) {
	content := readCLIFixture(t, "plan.json")
	path := writeRoot(t, "plan.json", content)
	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if errRes != nil || !out.Valid {
		t.Fatalf("valid plan doc must open valid: err=%v out=%+v", errRes, out)
	}
	if out.DocType != "plan" {
		t.Errorf("docType = %q, want plan", out.DocType)
	}
	if out.Summary == nil || out.Summary["assessmentCount"] == nil {
		t.Errorf("plan summary must carry assessmentCount, got %+v", out.Summary)
	}
}

func TestHdfOpen_BaselineSummary(t *testing.T) {
	path := writeRoot(t, "baseline.json", fixtures.Baseline.Win2022Stig)
	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if errRes != nil || !out.Valid || out.DocType != "baseline" {
		t.Fatalf("valid baseline must open valid: err=%v out=%+v", errRes, out)
	}
	if out.Summary == nil || out.Summary["requirementCount"] == nil {
		t.Errorf("baseline summary must carry requirementCount, got %+v", out.Summary)
	}
}

// readCLIFixture reads a real HDF fixture from the CLI's evidence-verify testdata.
func readCLIFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "cmd", "hdf", "cmd", "testdata", "evidence-verify", name))
	if err != nil {
		t.Skipf("CLI fixture %s unavailable: %v", name, err)
	}
	return b
}

func TestHdfOpen_OneShotPath_NoPriorHandle(t *testing.T) {
	path := writeRoot(t, "scan.json", fixtures.Results.Minimal)
	// A never-opened path succeeds in a single call with the full response.
	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if errRes != nil || !out.Valid || out.Handle == "" || out.Summary == nil {
		t.Fatalf("one-shot path call must return a full valid response: err=%v out=%+v", errRes, out)
	}
}

func TestHdfOpen_HandleRoundTrip_SameIdentity(t *testing.T) {
	path := writeRoot(t, "scan.json", fixtures.Results.Minimal)
	_, out1 := callOpen(t, openInput{Source: handle.Source{Path: path}})

	// Re-open by the minted handle → same identity.
	_, out2 := callOpen(t, openInput{Source: handle.Source{Handle: out1.Handle}})
	if out2.Handle != out1.Handle {
		t.Errorf("re-opening by handle should yield the same handle:\n %s\n %s", out1.Handle, out2.Handle)
	}
	if !out2.Valid || out2.DocType != "results" {
		t.Errorf("handle re-open lost validity/type: %+v", out2)
	}
}

func TestHdfOpen_DegradedOnInvalid(t *testing.T) {
	// Real-but-schema-invalid results doc (baselines as a string): detected as
	// results, fails validation → degraded read, NOT a hard error.
	bad := []byte("{\n  \"baselines\": \"not an array\",\n  \"components\": [],\n  \"statistics\": {}\n}")
	path := writeRoot(t, "bad.json", bad)

	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if errRes != nil {
		t.Fatalf("invalid HDF must degrade, not hard-fail: %+v", errRes)
	}
	if out.Valid {
		t.Error("invalid doc should be valid=false")
	}
	if out.DocType != "results" {
		t.Errorf("degraded read should still detect docType=results, got %q", out.DocType)
	}
	if len(out.ValidationErrors) == 0 {
		t.Fatal("degraded read must carry validationErrors")
	}
	hasLine := false
	for _, e := range out.ValidationErrors {
		if e.Line > 0 {
			hasLine = true
		}
	}
	if !hasLine {
		t.Error("degraded validationErrors should carry line numbers")
	}
}

func TestHdfOpen_PathDenied(t *testing.T) {
	writeRoot(t, "scan.json", fixtures.Results.Minimal) // sets HDF_MCP_ROOT
	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: "../../../../etc/passwd"}})
	if errRes == nil || !errRes.IsError {
		t.Fatalf("a path escaping HDF_MCP_ROOT must be an isError result, got out=%+v", out)
	}
	if !strings.Contains(payloadText(t, errRes), "PATH_DENIED") {
		t.Errorf("expected PATH_DENIED, got %s", payloadText(t, errRes))
	}
}

func TestHdfOpen_AmbiguousAndEmptySource(t *testing.T) {
	writeRoot(t, "scan.json", fixtures.Results.Minimal)
	// Both path and handle set, and neither set, are caller-argument mistakes:
	// code-less argError results, NOT the document codes they used to borrow
	// (AMBIGUOUS_FORMAT / DOCUMENT_NOT_FOUND).
	errRes, _ := callOpen(t, openInput{Source: handle.Source{Path: "scan.json", Handle: "x"}})
	assertArgError(t, errRes, "both path and handle")
	if strings.Contains(payloadText(t, errRes), "AMBIGUOUS_FORMAT") {
		t.Error("both path and handle must not borrow the AMBIGUOUS_FORMAT document code")
	}
	errRes2, _ := callOpen(t, openInput{Source: handle.Source{}})
	assertArgError(t, errRes2, "neither path nor handle")
	if strings.Contains(payloadText(t, errRes2), "DOCUMENT_NOT_FOUND") {
		t.Error("neither path nor handle must not borrow the DOCUMENT_NOT_FOUND document code")
	}
}

// assertArgError asserts res is a code-less caller-argument error (the argError
// shape): an isError result carrying no taxonomy code, whose payload contains
// want. This is the discriminator between a caller mistake and a document
// condition — a taxonomy error would carry a non-empty Code.
func assertArgError(t *testing.T, res *sdkmcp.CallToolResult, want string) {
	t.Helper()
	if res == nil || !res.IsError {
		t.Fatalf("expected an isError argument result, got %+v", res)
	}
	if tr := toolResultPayload(t, res); tr.Code != "" {
		t.Errorf("argument error must carry no taxonomy code, got %q", tr.Code)
	}
	if txt := payloadText(t, res); !strings.Contains(txt, want) {
		t.Errorf("argument error payload = %s, want substring %q", txt, want)
	}
}

func TestHdfOpen_StaleHandle(t *testing.T) {
	path := writeRoot(t, "scan.json", fixtures.Results.Minimal)
	_, out := callOpen(t, openInput{Source: handle.Source{Path: path}})
	// Mutate the file so the handle's content hash no longer matches.
	root := os.Getenv("HDF_MCP_ROOT")
	if err := os.WriteFile(filepath.Join(root, "scan.json"), []byte(`{"baselines":[],"components":[],"statistics":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	errRes, _ := callOpen(t, openInput{Source: handle.Source{Handle: out.Handle}})
	if errRes == nil || !strings.Contains(payloadText(t, errRes), "HANDLE_STALE") {
		t.Error("a changed file must make the handle HANDLE_STALE")
	}
}

func TestBoundOpenResponse_TruncatesWithNotice(t *testing.T) {
	// Many validation errors push the response past the 1k cap; the head is kept
	// and a notice names the narrowing next call.
	out := openOutput{Handle: "h", DocType: "results", Valid: false}
	for i := 0; i < 500; i++ {
		out.ValidationErrors = append(out.ValidationErrors, validationError{
			Line: i, Field: "baselines.0.requirements.99.descriptions", Description: "some descriptive validation failure text that consumes tokens",
		})
	}
	boundOpenResponse(&out)
	if len(out.ValidationErrors) >= 500 {
		t.Errorf("expected truncation, kept %d of 500", len(out.ValidationErrors))
	}
	if out.Notice == "" || !strings.Contains(out.Notice, "hdf_validate") {
		t.Errorf("truncation notice must name the narrowing next call, got %q", out.Notice)
	}
}

func TestHdfOpen_AnnotationsReadOnlyClosedWorld(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterOpen(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	if !strings.Contains(raw, `"name":"hdf_open"`) {
		t.Fatalf("hdf_open not listed: %s", raw)
	}
	if !strings.Contains(raw, `"readOnlyHint":true`) {
		t.Errorf("hdf_open must set readOnlyHint:true; got %s", raw)
	}
	if !strings.Contains(raw, `"openWorldHint":false`) {
		t.Errorf("hdf_open must set openWorldHint:false; got %s", raw)
	}
}

func TestHdfOpen_DocumentNotFound(t *testing.T) {
	writeRoot(t, "present.json", fixtures.Results.Minimal) // sets HDF_MCP_ROOT
	errRes, _ := callOpen(t, openInput{Source: handle.Source{Path: "missing.json"}})
	if errRes == nil || !strings.Contains(payloadText(t, errRes), "DOCUMENT_NOT_FOUND") {
		t.Errorf("a missing file must be DOCUMENT_NOT_FOUND, got %s", payloadText(t, errRes))
	}
}

func TestHdfOpen_MalformedHandle(t *testing.T) {
	writeRoot(t, "x.json", fixtures.Results.Minimal)
	// An undecodable handle is a caller mistake (garbage argument), not a stale
	// handle: it returns a code-less argError, not HANDLE_STALE (reserved for a
	// valid handle whose referenced file changed).
	errRes, _ := callOpen(t, openInput{Source: handle.Source{Handle: "!!!not-base64!!!"}})
	assertArgError(t, errRes, "not a valid hdf_open handle")
	if strings.Contains(payloadText(t, errRes), "HANDLE_STALE") {
		t.Error("a malformed handle must not borrow the HANDLE_STALE code")
	}
}

func TestHdfOpen_TooLarge(t *testing.T) {
	path := writeRoot(t, "big.json", fixtures.Results.Minimal)
	// A 4-byte per-document limit makes any real fixture too large.
	res, out, err := hdfOpen(loader.New(4, 0, 0))(context.Background(), nil, openInput{Source: handle.Source{Path: path}})
	if err != nil {
		t.Fatalf("size guard should be a taxonomy result, not a Go error: %v", err)
	}
	if res == nil || !strings.Contains(payloadText(t, res), "TOO_LARGE") {
		t.Errorf("an oversized document must be TOO_LARGE, got res=%v out=%+v", res, out)
	}
}

func TestRegisterAll_ListsHdfOpen(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterAll(s)
	if !strings.Contains(driveToolsListJSON(t, s), `"name":"hdf_open"`) {
		t.Error("RegisterAll must register hdf_open")
	}
}

func TestMcpRoot_DefaultsToCwd(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", "")
	if mcpRoot() == "" {
		t.Error("mcpRoot must fall back to a non-empty working directory")
	}
	t.Setenv("HDF_MCP_ROOT", "/some/root")
	if mcpRoot() != "/some/root" {
		t.Error("mcpRoot must honor HDF_MCP_ROOT when set")
	}
}

func TestSummaries_NilOnBadContent(t *testing.T) {
	if systemSummary([]byte("not json")) != nil {
		t.Error("systemSummary must return nil on unparseable content")
	}
	if planSummary([]byte("not json")) != nil {
		t.Error("planSummary must return nil on unparseable content")
	}
	if resultsSummary(nil) != nil || baselineSummary(nil) != nil {
		t.Error("summaries must return nil on a nil document")
	}
	if summarize(&hdfengine.LoadResult{DocType: "amendments"}, nil) != nil {
		t.Error("summarize must return nil for an unsummarized type")
	}
}

func payloadText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

// driveToolsListJSON runs the server over a pipe transport and returns the raw
// tools/list result JSON (for annotation inspection).
func driveToolsListJSON(t *testing.T, s *sdkmcp.Server) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5e9)
	defer cancel()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() { _ = s.Run(ctx, &sdkmcp.IOTransport{Reader: reqR, Writer: respW}); _ = respW.Close() }()
	go func() {
		_, _ = reqW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"))
	}()
	dec := json.NewDecoder(respR)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("no tools/list response: %v", err)
		}
		if m["id"] == float64(2) {
			b, _ := json.Marshal(m["result"])
			_ = reqW.Close()
			cancel()
			return string(b)
		}
	}
}
