package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callAuthor(t *testing.T, in authorInput) (*sdkmcp.CallToolResult, authorOutput) {
	t.Helper()
	res, out, err := hdfAuthor(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfAuthor returned a Go error (should use taxonomy paths): %v", err)
	}
	return res, out
}

// fixtureContent reads a real system/plan/evidence fixture and returns its
// content array as []map[string]any (components / assessments / contents).
func fixtureContent(t *testing.T, file, key string) []map[string]any {
	t.Helper()
	p := filepath.Join("..", "..", "..", "cmd", "hdf", "cmd", "testdata", "evidence-verify", file)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", file, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	arr, ok := doc[key].([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("%s has no %s array", file, key)
	}
	out := make([]map[string]any, len(arr))
	for i, v := range arr {
		out[i] = v.(map[string]any)
	}
	return out
}

var authorKinds = []struct {
	docType string
	file    string
	key     string
}{
	{"system", "system.json", "components"},
	{"plan", "plan.json", "assessments"},
	{"evidence", "evidence.json", "contents"},
}

// The card's designated first-failing test (generalized to the single authoring
// tool): each kind builds a schema-valid document.
func TestHdfAuthor_EachKind_ValidOutput(t *testing.T) {
	for _, k := range authorKinds {
		t.Run(k.docType, func(t *testing.T) {
			content := fixtureContent(t, k.file, k.key)
			res, out := callAuthor(t, authorInput{DocType: k.docType, Name: "Test " + k.docType, Content: content})
			if res != nil {
				t.Fatalf("valid content must not error: %s", payloadText(t, res))
			}
			if !out.Valid || out.DocType != k.docType || out.ItemCount != len(content) {
				t.Fatalf("unexpected summary: %+v", out)
			}
			if out.Handle == "" || out.Sha256 == "" {
				t.Fatalf("summary must carry handle + sha256: %+v", out)
			}
			// Summary-only: the document body must never be in the response.
			blob := mustJSON(&out)
			for _, forbidden := range []string{"\"components\"", "\"assessments\"", "\"contents\"", "\"generator\""} {
				if strings.Contains(blob, forbidden) {
					t.Fatalf("response leaked document body (%s): %s", forbidden, blob)
				}
			}
		})
	}
}

// TestHdfAuthor_RoundTripPreservesContent is the data-preservation guarantee:
// content fed through the tool and written to disk comes back field-for-field
// identical to the original fixture — nothing dropped or re-typed.
func TestHdfAuthor_RoundTripPreservesContent(t *testing.T) {
	for _, k := range authorKinds {
		t.Run(k.docType, func(t *testing.T) {
			t.Setenv("HDF_MCP_ROOT", t.TempDir())
			t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
			content := fixtureContent(t, k.file, k.key)

			_, out := callAuthor(t, authorInput{DocType: k.docType, Name: "RT " + k.docType, Content: content, Output: "out.json"})
			if out.OutputPath != "out.json" {
				t.Fatalf("write failed: %+v", out)
			}

			written, err := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json"))
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(written, &doc); err != nil {
				t.Fatal(err)
			}

			// The written content array must equal the original fixture content,
			// field-for-field — no loss, no reordering within items.
			gotArr, _ := json.Marshal(doc[k.key])
			var got, want any
			_ = json.Unmarshal(gotArr, &got)
			want = toAnySlice(content)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("content NOT preserved through the tool:\n got=%s\nwant=%v", gotArr, want)
			}
		})
	}
}

func toAnySlice(in []map[string]any) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func TestHdfAuthor_DryRun(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	content := fixtureContent(t, "system.json", "components")
	_, out := callAuthor(t, authorInput{DocType: "system", Name: "S", Content: content, Output: "out.json", DryRun: true})
	if out.OutputPath != "" || out.Notice == "" {
		t.Fatalf("dry_run must not write + must carry a notice: %+v", out)
	}
	if !out.Valid || out.Sha256 == "" {
		t.Fatal("dry_run must still return the summary")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json")); !os.IsNotExist(err) {
		t.Fatal("dry_run must not create a file")
	}
}

func TestHdfAuthor_WritesDisabled(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	content := fixtureContent(t, "plan.json", "assessments")
	_, out := callAuthor(t, authorInput{DocType: "plan", Name: "P", Content: content, Output: "out.json"})
	if out.OutputPath != "" || !out.WritesDisabled || !strings.Contains(out.Notice, "WRITES_DISABLED") {
		t.Fatalf("writes-disabled must preview, not write: %+v", out)
	}
	if !out.Valid {
		t.Fatal("writes-disabled must still return the summary")
	}
}

func TestHdfAuthor_RefusesSchemaInvalid(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	// A component missing its required fields fails schema validation → refused.
	res, _ := callAuthor(t, authorInput{
		DocType: "system", Name: "S", Content: []map[string]any{{"not": "a valid component"}}, Output: "out.json",
	})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "SCHEMA_INVALID") {
		t.Fatalf("invalid content must be refused with SCHEMA_INVALID: %s", payloadTextOrEmpty(res))
	}
	// The recovery hint must steer to the cheap per-$def schema slice, not the
	// expensive whole-schema resource (jobi.2 / D5).
	tr := toolResultPayload(t, res)
	if !strings.Contains(tr.NextCall, "slice") || !strings.Contains(tr.NextCall, "hdf://schema/hdf-system/") {
		t.Errorf("SchemaInvalid nextCall should point at the per-def slice, got %q", tr.NextCall)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json")); !os.IsNotExist(err) {
		t.Fatal("refused document must not be written")
	}
}

func TestHdfAuthor_EmptyContentRefused(t *testing.T) {
	// The content array is minItems:1 — an empty one is schema-invalid.
	res, _ := callAuthor(t, authorInput{DocType: "system", Name: "S", Content: []map[string]any{}})
	if res == nil || !res.IsError {
		t.Fatal("empty content must be refused")
	}
}

func TestHdfAuthor_UnknownDocType(t *testing.T) {
	res, _ := callAuthor(t, authorInput{DocType: "comparison", Name: "A", Content: []map[string]any{{"x": 1}}})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "unknown docType") {
		t.Fatalf("an unsupported docType must be an isError result: %s", payloadTextOrEmpty(res))
	}
}

func TestHdfAuthor_PureCompute_NoWrite(t *testing.T) {
	content := fixtureContent(t, "evidence.json", "contents")
	_, out := callAuthor(t, authorInput{DocType: "evidence", Name: "E", Content: content})
	if out.OutputPath != "" || out.Notice != "" {
		t.Fatalf("no output → no write, no notice: %+v", out)
	}
	if out.Handle == "" || !out.Valid {
		t.Fatal("pure compute must still return a valid summary + handle")
	}
}

func TestHdfAuthor_HandleRoundTrips(t *testing.T) {
	content := fixtureContent(t, "system.json", "components")
	_, out := callAuthor(t, authorInput{DocType: "system", Name: "S", Content: content, Output: "s.json"})
	h, err := handle.Decode(out.Handle)
	if err != nil {
		t.Fatalf("handle must decode: %v", err)
	}
	if h.DocType != "system" {
		t.Fatalf("handle docType = %q, want system", h.DocType)
	}
}

func TestHdfAuthor_PathDenied(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	content := fixtureContent(t, "system.json", "components")
	res, _ := callAuthor(t, authorInput{DocType: "system", Name: "S", Content: content, Output: "../../../etc/x.json"})
	if res == nil || !res.IsError {
		t.Fatal("an output path escaping HDF_MCP_ROOT must be denied")
	}
}

func TestHdfAuthor_RefusesSchemaInvalid_Evidence(t *testing.T) {
	res, _ := callAuthor(t, authorInput{
		DocType: "evidence", Name: "E", Content: []map[string]any{{"not": "a valid content ref"}},
	})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "evidence-package") {
		t.Fatalf("invalid evidence must be refused and point at the evidence-package resource: %s", payloadTextOrEmpty(res))
	}
}

// ---- amendments authoring (docType=amendments) --------------------------

// validJudgmentOverride is an override as a model would supply it on the
// judgment path: it carries the model's selection + reason + type + caller
// expiry, but NOT appliedBy/appliedAt — those are the server's to stamp.
func validJudgmentOverride() map[string]any {
	return map[string]any{
		"type":          "riskAdjustment",
		"requirementId": "V-1234",
		"reason":        "Compensating control in place; residual risk accepted for this cycle.",
		"status":        "notApplicable",
		"expiresAt":     "2099-12-31T00:00:00Z",
	}
}

func readAmendments(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func firstOverride(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	arr, ok := doc["overrides"].([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("no overrides in written amendments: %v", doc)
	}
	ov, ok := arr[0].(map[string]any)
	if !ok {
		t.Fatalf("override is not an object: %v", arr[0])
	}
	return ov
}

// The judgment path: the server stamps appliedBy.type=agent + appliedAt and
// preserves the model's fields.
func TestHdfAuthor_Amendments_JudgmentPath_StampsAgent(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	res, out := callAuthor(t, authorInput{
		DocType: "amendments", Name: "Risk decisions", Content: []map[string]any{validJudgmentOverride()}, Output: "a.json",
	})
	if res != nil {
		t.Fatalf("a valid judgment amendment must not error: %s", payloadText(t, res))
	}
	if !out.Valid || out.DocType != "amendments" || out.ItemCount != 1 || out.OutputPath != "a.json" {
		t.Fatalf("unexpected summary: %+v", out)
	}
	ov := firstOverride(t, readAmendments(t, filepath.Join(os.Getenv("HDF_MCP_ROOT"), "a.json")))
	ab, _ := ov["appliedBy"].(map[string]any)
	if ab == nil || ab["type"] != "agent" {
		t.Fatalf("appliedBy.type must be stamped agent: %v", ov["appliedBy"])
	}
	if s, _ := ov["appliedAt"].(string); s == "" {
		t.Fatalf("appliedAt must be stamped: %v", ov)
	}
	// Model fields preserved.
	if ov["type"] != "riskAdjustment" || ov["requirementId"] != "V-1234" || ov["expiresAt"] != "2099-12-31T00:00:00Z" {
		t.Fatalf("model fields not preserved: %v", ov)
	}
}

// The card's first-failing test: a judgment override with no expiresAt is
// rejected up front (SCHEMA_INVALID), never defaulted or written.
func TestHdfAuthor_Amendments_ExpiresAtRequired(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	ov := validJudgmentOverride()
	delete(ov, "expiresAt")
	res, _ := callAuthor(t, authorInput{DocType: "amendments", Name: "R", Content: []map[string]any{ov}, Output: "a.json"})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "SCHEMA_INVALID") {
		t.Fatalf("a missing expiresAt must be refused with SCHEMA_INVALID: %s", payloadTextOrEmpty(res))
	}
	if !strings.Contains(payloadText(t, res), "expiresAt") {
		t.Fatalf("the error should name expiresAt: %s", payloadText(t, res))
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "a.json")); !os.IsNotExist(err) {
		t.Fatal("a refused amendment must not be written")
	}
}

// appliedBy.type is fixed by the server: a model-supplied type is overridden to
// agent (keeps the agent-override count honest).
func TestHdfAuthor_Amendments_AppliedByType_ServerFixed_ModelCannotOverride(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	ov := validJudgmentOverride()
	ov["appliedBy"] = map[string]any{"identifier": "jdoe", "type": "username"}
	_, out := callAuthor(t, authorInput{DocType: "amendments", Name: "R", Content: []map[string]any{ov}, Output: "a.json"})
	if out.OutputPath != "a.json" {
		t.Fatalf("write failed: %+v", out)
	}
	got := firstOverride(t, readAmendments(t, filepath.Join(os.Getenv("HDF_MCP_ROOT"), "a.json")))
	ab, _ := got["appliedBy"].(map[string]any)
	if ab["type"] != "agent" {
		t.Fatalf("server must override appliedBy.type to agent, got %v", ab["type"])
	}
	if ab["identifier"] != "jdoe" {
		t.Fatalf("a model-supplied identifier should be preserved, got %v", ab["identifier"])
	}
}

func readVexFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", "multi-status.openvex.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("openvex fixture unavailable: %v", err)
	}
	dst := filepath.Join(os.Getenv("HDF_MCP_ROOT"), "vex.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return "vex.json"
}

// The from_vex path: overrides are derived deterministically from a VEX source
// and stamped appliedBy.type=system (a mapping is not agent judgment), with the
// caller expiresAt applied.
func TestHdfAuthor_Amendments_FromVex_StampsSystem(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	vex := readVexFixture(t)
	res, out := callAuthor(t, authorInput{
		DocType: "amendments", Name: "From VEX", Source: &handle.Source{Path: vex},
		ExpiresAt: "2099-12-31T00:00:00Z", Output: "a.json",
	})
	if res != nil {
		t.Fatalf("from_vex must not error: %s", payloadText(t, res))
	}
	if !out.Valid || out.ItemCount < 1 || out.OutputPath != "a.json" {
		t.Fatalf("unexpected summary: %+v", out)
	}
	ov := firstOverride(t, readAmendments(t, filepath.Join(os.Getenv("HDF_MCP_ROOT"), "a.json")))
	ab, _ := ov["appliedBy"].(map[string]any)
	if ab == nil || ab["type"] != "system" {
		t.Fatalf("from_vex overrides must be stamped system, got %v", ov["appliedBy"])
	}
	if ov["expiresAt"] != "2099-12-31T00:00:00Z" {
		t.Fatalf("caller expiresAt must be applied, got %v", ov["expiresAt"])
	}
}

func TestHdfAuthor_Amendments_FromVex_ExpiresAtRequired(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	vex := readVexFixture(t)
	res, _ := callAuthor(t, authorInput{
		DocType: "amendments", Name: "From VEX", Source: &handle.Source{Path: vex}, Output: "a.json",
	})
	if res == nil || !res.IsError {
		t.Fatal("from_vex with no expiresAt must be refused")
	}
	if !strings.Contains(payloadText(t, res), "expiresAt") && !strings.Contains(payloadText(t, res), "expires") {
		t.Fatalf("the error should name the missing expiry: %s", payloadText(t, res))
	}
}

func TestHdfAuthor_Amendments_SourceAndContentMutuallyExclusive(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	vex := readVexFixture(t)
	res, _ := callAuthor(t, authorInput{
		DocType: "amendments", Name: "R", Content: []map[string]any{validJudgmentOverride()},
		Source: &handle.Source{Path: vex}, ExpiresAt: "2099-12-31T00:00:00Z",
	})
	if res == nil || !res.IsError {
		t.Fatal("supplying both content (judgment) and source (from_vex) must be an error")
	}
}

func TestHdfAuthor_Amendments_NeitherContentNorSource(t *testing.T) {
	res, _ := callAuthor(t, authorInput{DocType: "amendments", Name: "R"})
	if res == nil || !res.IsError {
		t.Fatal("amendments with neither content nor source must be an error")
	}
}

func TestHdfAuthor_Amendments_FromVex_InvalidExpiresAt(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	vex := readVexFixture(t)
	res, _ := callAuthor(t, authorInput{
		DocType: "amendments", Name: "R", Source: &handle.Source{Path: vex}, ExpiresAt: "not-a-timestamp",
	})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "invalid expiresAt") {
		t.Fatalf("a non-RFC3339 expiresAt must be rejected: %s", payloadTextOrEmpty(res))
	}
}

func TestHdfAuthor_Amendments_FromVex_NoActionableStatements(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	// empty.openvex.json carries only affected + under_investigation → nothing maps.
	p := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", "empty.openvex.json")
	if _, err := os.Stat(p); err != nil {
		t.Skip("openvex fixture unavailable")
	}
	b, _ := os.ReadFile(p)
	dst := filepath.Join(os.Getenv("HDF_MCP_ROOT"), "empty-vex.json")
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ := callAuthor(t, authorInput{
		DocType: "amendments", Name: "R", Source: &handle.Source{Path: "empty-vex.json"}, ExpiresAt: "2099-12-31T00:00:00Z",
	})
	if res == nil || !res.IsError {
		t.Fatal("a VEX with no actionable statements must be refused, not emit an empty override set")
	}
}

func TestHdfAuthor_Amendments_FromVex_RejectsHandle(t *testing.T) {
	res, _ := callAuthor(t, authorInput{
		DocType: "amendments", Name: "R", Source: &handle.Source{Handle: "some-handle"}, ExpiresAt: "2099-12-31T00:00:00Z",
	})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "not an HDF handle") {
		t.Fatalf("from_vex takes a raw VEX by path, not an HDF handle: %s", payloadTextOrEmpty(res))
	}
}

func TestHdfAuthor_Amendments_FromVex_PathDenied(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	res, _ := callAuthor(t, authorInput{
		DocType: "amendments", Name: "R", Source: &handle.Source{Path: "../../../etc/passwd"}, ExpiresAt: "2099-12-31T00:00:00Z",
	})
	if res == nil || !res.IsError {
		t.Fatal("a from_vex source escaping HDF_MCP_ROOT must be denied")
	}
}

func TestHdfAuthor_Amendments_AssemblyErrorHandled(t *testing.T) {
	// A value json cannot marshal makes the builder fail; the tool must return a
	// taxonomy error, never panic. (expiresAt is present so stamping succeeds and
	// the failure surfaces at assembly.)
	ov := validJudgmentOverride()
	ov["bogus"] = make(chan int)
	res, _ := callAuthor(t, authorInput{DocType: "amendments", Name: "R", Content: []map[string]any{ov}})
	if res == nil || !res.IsError {
		t.Fatal("an unassemblable override must be an error, not a panic")
	}
}

func TestHdfAuthor_Amendments_DryRun(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	_, out := callAuthor(t, authorInput{
		DocType: "amendments", Name: "R", Content: []map[string]any{validJudgmentOverride()}, Output: "a.json", DryRun: true,
	})
	if out.OutputPath != "" || out.Notice == "" || !out.Valid {
		t.Fatalf("dry_run must preview a valid amendment without writing: %+v", out)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "a.json")); !os.IsNotExist(err) {
		t.Fatal("dry_run must not write a file")
	}
}
