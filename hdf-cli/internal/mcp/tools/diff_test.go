package tools

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callDiff(t *testing.T, in diffInput) (*sdkmcp.CallToolResult, diffOutput) {
	t.Helper()
	res, out, err := hdfDiff(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfDiff Go error (should be taxonomy tool result): %v", err)
	}
	return res, out
}

// TestHdfDiff_HonorsCancellation proves the handler respects the request
// context: a cancelled ctx propagates as a context.Canceled Go error rather than
// running the comparison or mislabeling it as a taxonomy error.
func TestHdfDiff_HonorsCancellation(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := hdfDiff(loader.New(0, 0, 0))(ctx, nil, diffInput{
		From: handle.Source{Path: "from.json"},
		To:   handle.Source{Path: "to.json"},
		Mode: "temporal",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from a cancelled diff, got %v", err)
	}
}

// writeRootFiles writes several fixtures into one HDF_MCP_ROOT and returns their
// relative names (writeRoot sets a fresh root per call, so multi-file tests need this).
func writeRootFiles(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

func changeByID(t *testing.T, rows []map[string]any, key, id string) map[string]any {
	t.Helper()
	for _, m := range rows {
		if m[key] == id {
			return m
		}
	}
	return nil
}

// The card's designated first-failing test: when output is set, the emitted
// document validates as hdf-comparison via hdf-validators (not just as JSON).
func TestHdfDiff_EmitsValidComparison(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	res, out := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Output: "comp.json",
	})
	if res != nil {
		t.Fatalf("valid temporal diff must not error: %s", payloadText(t, res))
	}
	if out.OutputPath != "comp.json" || out.Sha256 == "" || !out.Valid {
		t.Fatalf("emit must report path+sha256+valid, got %+v", out)
	}
	// Re-validate the file on disk independently.
	data, err := os.ReadFile(filepath.Join(root, "comp.json"))
	if err != nil {
		t.Fatal(err)
	}
	vr := validators.Validate(data, validators.TypeComparison)
	if !vr.Valid {
		t.Errorf("emitted document must validate as hdf-comparison; errors: %v", vr.Errors)
	}
}

func TestHdfDiff_TemporalSummaryAndChanges(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	_, out := callDiff(t, diffInput{From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Mode: "temporal"})
	if out.Mode != "temporal" {
		t.Errorf("mode = %q, want temporal", out.Mode)
	}
	if out.Summary.Fixed != 1 || out.Summary.Regressed != 1 || out.Summary.Total != 2 {
		t.Errorf("summary = %+v, want fixed=1 regressed=1 total=2", out.Summary)
	}
	fix := changeByID(t, out.Changes, "id", "V-FIX-01")
	reg := changeByID(t, out.Changes, "id", "V-REG-02")
	if fix == nil || fix["state"] != "fixed" {
		t.Errorf("V-FIX-01 must be fixed, got %v", fix)
	}
	if reg == nil || reg["state"] != "regressed" {
		t.Errorf("V-REG-02 must be regressed, got %v", reg)
	}
}

// The v3.5.0 Change_Reason additions must surface in the change list, not be
// dropped or cause an error.
func TestHdfDiff_ToleratesV350ChangeReasons(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	_, out := callDiff(t, diffInput{From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}})
	fix := changeByID(t, out.Changes, "id", "V-FIX-01")
	if fix == nil {
		t.Fatal("V-FIX-01 change row missing")
	}
	reasons, _ := json.Marshal(fix["changeReasons"])
	for _, want := range []string{"dispositionChanged", "effectiveImpactChanged"} {
		if !strings.Contains(string(reasons), want) {
			t.Errorf("change reasons must surface %q; got %s", want, reasons)
		}
	}
}

func TestHdfDiff_WritesDisabledPreview(t *testing.T) {
	// Writes disabled (the deployer-ceiling default): an output-giving diff must
	// return the summary + a WRITES_DISABLED notice and write NO file — not error.
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	root := writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	res, out := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Output: "comp.json",
	})
	if res != nil {
		t.Fatalf("writes-disabled must be a successful preview, not an error: %s", payloadText(t, res))
	}
	if out.OutputPath != "" {
		t.Fatalf("writes-disabled must not write a path, got %q", out.OutputPath)
	}
	if !out.WritesDisabled || !strings.Contains(out.Notice, "WRITES_DISABLED") {
		t.Fatalf("expected a WRITES_DISABLED flag + notice, got %+v", out)
	}
	if out.Sha256 == "" || !out.Valid {
		t.Fatalf("the preview must still report the would-be sha256 + validity, got %+v", out)
	}
	if _, err := os.Stat(filepath.Join(root, "comp.json")); !os.IsNotExist(err) {
		t.Fatal("writes-disabled must not create a file")
	}
}

func TestHdfDiff_WriteNoticePreservesOtherNotice(t *testing.T) {
	// A write-model notice must be appended to, not clobber, a notice
	// buildDiffResponse already set (here, an out-of-range page).
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	_, out := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"},
		Output: "comp.json", Page: 99,
	})
	if !strings.Contains(out.Notice, "out of range") {
		t.Fatalf("page notice lost: %q", out.Notice)
	}
	if !strings.Contains(out.Notice, "WRITES_DISABLED") || !out.WritesDisabled {
		t.Fatalf("write notice/flag lost: notice=%q writesDisabled=%v", out.Notice, out.WritesDisabled)
	}
}

func TestHdfDiff_DryRunPreview(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	_, out := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Output: "comp.json", DryRun: true,
	})
	if out.OutputPath != "" {
		t.Fatalf("dry_run must not write, got path %q", out.OutputPath)
	}
	if out.Notice == "" {
		t.Fatal("dry_run must carry a preview notice")
	}
	if out.Sha256 == "" {
		t.Fatal("dry_run should still report the would-be sha256")
	}
	if _, err := os.Stat(filepath.Join(root, "comp.json")); !os.IsNotExist(err) {
		t.Fatal("dry_run must not create a file")
	}
}

func TestHdfDiff_SystemDrift(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-system-from.json"),
		"to.json":   readToolsFixture(t, "diff-system-to.json"),
	})
	res, out := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"},
		Mode: "system-drift", Output: "comp.json",
	})
	if res != nil {
		t.Fatalf("system-drift diff must not error: %s", payloadText(t, res))
	}
	// WebTier updated, DatabaseTier absent, CacheTier new — three component changes.
	web := changeByID(t, out.Changes, "name", "WebTier")
	db := changeByID(t, out.Changes, "name", "DatabaseTier")
	cache := changeByID(t, out.Changes, "name", "CacheTier")
	if web == nil || web["state"] != "updated" {
		t.Errorf("WebTier must be updated, got %v", web)
	}
	if db == nil || db["state"] != "absent" {
		t.Errorf("DatabaseTier must be absent, got %v", db)
	}
	if cache == nil || cache["state"] != "new" {
		t.Errorf("CacheTier must be new, got %v", cache)
	}
	// The emitted system-drift comparison validates (locks the null-fieldChanges engine fix).
	data, _ := os.ReadFile(filepath.Join(root, "comp.json"))
	if vr := validators.Validate(data, validators.TypeComparison); !vr.Valid {
		t.Errorf("emitted system-drift comparison must validate; errors: %v", vr.Errors)
	}

	// full verbosity carries per-component field changes (WebTier changed description).
	_, full := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Mode: "system-drift", Verbosity: "full",
	})
	webFull := changeByID(t, full.Changes, "name", "WebTier")
	if webFull == nil {
		t.Fatal("WebTier full row missing")
	}
	if _, has := webFull["fieldChanges"]; !has {
		t.Error("full system-drift row must carry fieldChanges")
	}
}

func TestHdfDiff_VerbosityConciseVsFull(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	_, concise := callDiff(t, diffInput{From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Verbosity: "concise"})
	_, full := callDiff(t, diffInput{From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Verbosity: "full"})

	// Concise rows carry exactly id/state/changeReasons/oldStatus/newStatus (no fieldChanges).
	crow := changeByID(t, concise.Changes, "id", "V-FIX-01")
	if _, has := crow["fieldChanges"]; has {
		t.Error("concise row must not carry fieldChanges")
	}
	if _, has := crow["oldStatus"]; !has {
		t.Error("concise row must carry oldStatus")
	}
	// Full rows are richer.
	frow := changeByID(t, full.Changes, "id", "V-FIX-01")
	if _, has := frow["baseline"]; !has {
		t.Error("full row should carry baseline")
	}
}

func TestHdfDiff_HandleSources(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	_, fromOpen := callOpen(t, openInput{Source: handle.Source{Path: "from.json"}})
	_, toOpen := callOpen(t, openInput{Source: handle.Source{Path: "to.json"}})
	_, out := callDiff(t, diffInput{
		From: handle.Source{Handle: fromOpen.Handle}, To: handle.Source{Handle: toOpen.Handle},
	})
	if out.Summary.Total != 2 {
		t.Errorf("handle sources must resolve; summary total = %d, want 2", out.Summary.Total)
	}
}

func TestHdfDiff_WrongDocTypeForMode(t *testing.T) {
	// temporal mode given a system document.
	writeRootFiles(t, map[string][]byte{
		"sys.json": readToolsFixture(t, "diff-system-from.json"),
		"to.json":  readToolsFixture(t, "diff-to.json"),
	})
	res, _ := callDiff(t, diffInput{From: handle.Source{Path: "sys.json"}, To: handle.Source{Path: "to.json"}, Mode: "temporal"})
	if res == nil || !res.IsError {
		t.Fatal("temporal mode with a system document must error")
	}
	tr := toolResultPayload(t, res)
	if tr.Code != mcperr.WrongDocType {
		t.Errorf("code = %q, want WRONG_DOC_TYPE", tr.Code)
	}
	if !strings.Contains(tr.NextCall, "system-drift") {
		t.Errorf("remedy should mention the other mode, got %q", tr.NextCall)
	}
}

func TestHdfDiff_UnknownMode(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	res, _ := callDiff(t, diffInput{From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Mode: "bogus"})
	assertArgError(t, res, "unknown mode")
}

func TestHdfDiff_OutputPathDenied(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	res, _ := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Output: "../escape.json",
	})
	if res == nil || !res.IsError {
		t.Fatal("an output path escaping the root must error")
	}
	if tr := toolResultPayload(t, res); tr.Code != mcperr.PathDenied {
		t.Errorf("code = %q, want PATH_DENIED", tr.Code)
	}
}

func TestHdfDiff_Annotations(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterDiff(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	if !strings.Contains(raw, `"name":"hdf_diff"`) {
		t.Fatalf("hdf_diff not listed: %s", raw)
	}
	if !strings.Contains(raw, `"readOnlyHint":true`) || !strings.Contains(raw, `"openWorldHint":false`) {
		t.Errorf("hdf_diff must be read-only + closed-world: %s", raw)
	}
}

func TestHdfDiff_SchemaInvalidSource(t *testing.T) {
	bad := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"x","descriptions":[],"impact":5,"tags":{},"results":[]}]}],"statistics":{"duration":1}}`)
	writeRootFiles(t, map[string][]byte{
		"bad.json": bad,
		"to.json":  readToolsFixture(t, "diff-to.json"),
	})
	res, _ := callDiff(t, diffInput{From: handle.Source{Path: "bad.json"}, To: handle.Source{Path: "to.json"}})
	if res == nil || !res.IsError {
		t.Fatal("a schema-invalid source must error")
	}
	if tr := toolResultPayload(t, res); tr.Code != mcperr.SchemaInvalid {
		t.Errorf("code = %q, want SCHEMA_INVALID", tr.Code)
	}
}

func TestHdfDiff_OutputDirMissing(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	res, _ := callDiff(t, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"}, Output: "no-such-dir/comp.json",
	})
	if res == nil || !res.IsError {
		t.Fatal("writing under a missing directory must error")
	}
	// A missing parent directory is a write failure, not a missing document to
	// read — WRITE_FAILED, not DOCUMENT_NOT_FOUND.
	if tr := toolResultPayload(t, res); tr.Code != mcperr.WriteFailed {
		t.Errorf("code = %q, want WRITE_FAILED", tr.Code)
	}
}

func TestBuildDiffResponse_TruncatesAndPaginates(t *testing.T) {
	rows := make([]map[string]any, 0, 300)
	for i := 0; i < 300; i++ {
		rows = append(rows, structToMap(temporalConcise{
			ID: "V-" + strings.Repeat("x", 3) + itoa(i), State: "updated",
			ChangeReasons: []diff.ChangeReason{diff.ReasonResultChanged}, OldStatus: "failed", NewStatus: "passed",
		}))
	}
	out := diffOutput{Mode: "temporal", FromHandle: "h1", ToHandle: "h2"}
	buildDiffResponse(&out, rows, "concise", 0)
	if out.Total != 300 {
		t.Errorf("total = %d, want 300", out.Total)
	}
	if !out.Truncated || out.NextPage != 1 || out.Notice == "" {
		t.Errorf("a large change list must truncate with nextPage=1 + notice, got %+v", out)
	}
	if out.Returned == 0 || out.Returned >= 300 {
		t.Errorf("first page must be a bounded subset, got returned=%d", out.Returned)
	}
	// Page out of range → empty changes + notice.
	oob := diffOutput{Mode: "temporal"}
	buildDiffResponse(&oob, rows, "concise", 999)
	if len(oob.Changes) != 0 || !oob.Truncated || oob.Notice == "" {
		t.Errorf("out-of-range page must return no changes + a notice, got %+v", oob)
	}
}

func TestPaginateChanges_DisjointWindows(t *testing.T) {
	rows := make([]map[string]any, 0, 300)
	for i := 0; i < 300; i++ {
		rows = append(rows, structToMap(temporalConcise{
			ID: "V-" + strings.Repeat("x", 3) + itoa(i), State: "updated",
			OldStatus: "failed", NewStatus: "passed",
		}))
	}
	base := diffOutput{Mode: "temporal", FromHandle: "h1", ToHandle: "h2"}
	sizeOf := func(page []map[string]any) int {
		trial := base
		trial.Changes = page
		trial.Truncated = true
		trial.NextPage = 1
		return respond.EstimateTokens(mustJSON(&trial))
	}
	pages := respond.Paginate(rows, 800, sizeOf)
	if len(pages) < 2 {
		t.Fatalf("expected multiple pages, got %d", len(pages))
	}
	seen := map[string]bool{}
	for _, pg := range pages {
		for _, id := range ids(pg) {
			if seen[id] {
				t.Errorf("id %q on more than one page", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 300 {
		t.Errorf("pages must cover every row once, covered %d/300", len(seen))
	}
}

func TestHdfDiff_RefusesOverwritingInput(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeRootFiles(t, map[string][]byte{
		"from.json": readToolsFixture(t, "diff-from.json"),
		"to.json":   readToolsFixture(t, "diff-to.json"),
	})
	// output == an input document must be refused even with overwrite:true.
	res, _, err := hdfDiff(loader.New(0, 0, 0))(context.Background(), nil, diffInput{
		From: handle.Source{Path: "from.json"}, To: handle.Source{Path: "to.json"},
		Output: "from.json", Overwrite: true,
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res == nil {
		t.Fatal("writing the comparison over an input document must be refused, even with overwrite:true")
	}
}

// TestDiff_ErrorNextCallNamesOwnInputs — a document-not-found error from hdf_diff
// must name the slot the caller passed (from / to), never `source` (jobi.4 / D3).
func TestDiff_ErrorNextCallNamesOwnInputs(t *testing.T) {
	writeRootFiles(t, map[string][]byte{"to.json": readToolsFixture(t, "diff-to.json")})
	res, _ := callDiff(t, diffInput{From: handle.Source{Path: "nonexistent.json"}, To: handle.Source{Path: "to.json"}, Mode: "temporal"})
	tr := toolResultPayload(t, res)
	if !strings.Contains(tr.NextCall, "from") {
		t.Errorf("from-not-found nextCall must name `from`, got %q", tr.NextCall)
	}
	if strings.Contains(tr.NextCall, "source") {
		t.Errorf("nextCall leaked `source` — hdf_diff has no source input: %q", tr.NextCall)
	}
}
