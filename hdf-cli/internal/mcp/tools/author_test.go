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
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callAuthor(t *testing.T, in authorInput) (*sdkmcp.CallToolResult, authorOutput) {
	t.Helper()
	res, out, err := hdfAuthor()(context.Background(), nil, in)
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
	res, _ := callAuthor(t, authorInput{DocType: "amendments", Name: "A", Content: []map[string]any{{"x": 1}}})
	if res == nil || !res.IsError {
		t.Fatal("an unsupported docType must be an isError result")
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
