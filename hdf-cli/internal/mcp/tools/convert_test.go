package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callConvert(t *testing.T, in convertInput) (*sdkmcp.CallToolResult, convertOutput) {
	t.Helper()
	res, out, err := hdfConvert(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfConvert returned a Go error (should use taxonomy paths): %v", err)
	}
	return res, out
}

// gosecFixture reads a real gosec fixture that converts to a valid hdf-results
// document (1 baseline, 3 requirements).
func gosecFixture(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "gosec-to-hdf", "fixtures", "input", "grype-gosec.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("gosec fixture unavailable: %v", err)
	}
	return b
}

// The card's designated first-failing test.
func TestHdfConvert_SummaryOnly_NoArtifactBody(t *testing.T) {
	res, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "gosec"})
	if res != nil {
		t.Fatalf("valid conversion must not error: %s", payloadText(t, res))
	}
	if out.DocType != "results" || !out.Valid {
		t.Fatalf("expected valid results summary, got %+v", out)
	}
	if out.BaselineCount != 1 || out.RequirementCount != 3 {
		t.Fatalf("summary counts = %d baselines / %d reqs, want 1/3", out.BaselineCount, out.RequirementCount)
	}
	if out.Sha256 == "" || out.Handle == "" {
		t.Fatalf("summary must carry sha256 + handle, got %+v", out)
	}
	// The converted document body must NEVER appear in the response.
	blob := mustJSON(&out)
	for _, forbidden := range []string{"\"baselines\"", "\"requirements\"", "\"profiles\"", "\"code\""} {
		if strings.Contains(blob, forbidden) {
			t.Fatalf("response leaked document body (%s): %s", forbidden, blob)
		}
	}
}

func TestHdfConvert_AutoDetect(t *testing.T) {
	// from omitted → fingerprint detection.
	res, out := callConvert(t, convertInput{Content: string(gosecFixture(t))})
	if res != nil {
		t.Fatalf("auto-detected conversion must not error: %s", payloadText(t, res))
	}
	if !out.Valid || out.RequirementCount != 3 {
		t.Fatalf("auto-detect produced %+v", out)
	}
}

func TestHdfConvert_PureCompute_NoWrite(t *testing.T) {
	_, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "gosec"})
	if out.OutputPath != "" || out.Notice != "" {
		t.Fatalf("no output requested → no write, no notice: %+v", out)
	}
	if out.Handle == "" {
		t.Fatal("pure compute must still return a handle")
	}
}

func TestHdfConvert_WritesEnabled(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRoot(t, "scan.json", gosecFixture(t))
	_, out := callConvert(t, convertInput{Source: &handle.Source{Path: "scan.json"}, From: "gosec", Output: "out.json"})
	if out.OutputPath != "out.json" {
		t.Fatalf("enabled write should report the path, got %+v", out)
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json"))
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if !validators.ValidateResults(data).Valid {
		t.Fatal("written document must validate as hdf-results")
	}
}

func TestHdfConvert_RefusesOverwritingSourceInput(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRoot(t, "scan.json", gosecFixture(t))
	// output == the source path being read must be refused even with overwrite:true —
	// writing the converted result there would destroy the input mid-conversion.
	res, _ := callConvert(t, convertInput{
		Source: &handle.Source{Path: "scan.json"}, From: "gosec", Output: "scan.json", Overwrite: true,
	})
	if res == nil {
		t.Fatal("converting with output == source input must be refused, even with overwrite:true")
	}
	got, _ := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "scan.json"))
	if string(got) != string(gosecFixture(t)) {
		t.Fatal("the source input must be left intact")
	}
}

func TestHdfConvert_RefusesClobberWithoutOverwrite(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRoot(t, "out.json", []byte("precious existing data"))
	// Existing output, no overwrite → refused; the existing file is preserved.
	res, _ := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "gosec", Output: "out.json"})
	if res == nil {
		t.Fatal("writing over an existing output without overwrite must be refused")
	}
	got, _ := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json"))
	if string(got) != "precious existing data" {
		t.Fatalf("existing file must be preserved, got %q", got)
	}
	// With overwrite:true it replaces the file with valid HDF.
	_, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "gosec", Output: "out.json", Overwrite: true})
	if out.OutputPath != "out.json" {
		t.Fatalf("overwrite:true must write, got %+v", out)
	}
	got, _ = os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json"))
	if !validators.ValidateResults(got).Valid {
		t.Fatal("overwritten document must validate as hdf-results")
	}
}

func TestHdfConvert_DryRun(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	_, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "gosec", Output: "out.json", DryRun: true})
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

func TestHdfConvert_WritesDisabled(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	_, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "gosec", Output: "out.json"})
	if out.OutputPath != "" || !out.WritesDisabled || !strings.Contains(out.Notice, "WRITES_DISABLED") {
		t.Fatalf("writes-disabled must preview, not write: %+v", out)
	}
	if !out.Valid || out.Sha256 == "" {
		t.Fatal("writes-disabled must still return the summary")
	}
}

// awsConfigFixture reads a real aws-config fixture whose HDF output carries a
// component, so label/componentId threading is observable.
func awsConfigFixture(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "aws-config-to-hdf", "fixtures", "input", "minimal.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("aws-config fixture unavailable: %v", err)
	}
	return b
}

func TestHdfConvert_LabelsAndComponentIDThreaded(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	_, out := callConvert(t, convertInput{
		Content: string(awsConfigFixture(t)), From: "aws-config", Output: "out.json",
		Labels: map[string]string{"system": "Portal"}, ComponentID: "11111111-1111-1111-1111-111111111111",
	})
	if out.OutputPath != "out.json" {
		t.Fatalf("write failed: %+v", out)
	}
	data, _ := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json"))
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	comps, _ := doc["components"].([]any)
	if len(comps) == 0 {
		t.Fatal("aws-config output must carry a component to thread labels onto")
	}
	c0 := comps[0].(map[string]any)
	if c0["componentId"] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("componentId not threaded: %v", c0["componentId"])
	}
	labels, _ := c0["labels"].(map[string]any)
	if labels["system"] != "Portal" {
		t.Fatalf("label not threaded: %v", labels)
	}
}

func TestHdfConvert_UnknownFrom_NoConverter(t *testing.T) {
	res, _ := callConvert(t, convertInput{Content: `{"x":1}`, From: "not-a-real-format"})
	if res == nil || !res.IsError {
		t.Fatal("an unknown from must be an isError result")
	}
	if !strings.Contains(payloadText(t, res), "NO_CONVERTER") {
		t.Fatalf("expected NO_CONVERTER: %s", payloadText(t, res))
	}
}

func TestHdfConvert_NeitherSourceNorContent(t *testing.T) {
	res, _ := callConvert(t, convertInput{From: "gosec"})
	if res == nil || !res.IsError {
		t.Fatal("neither source nor content must be an isError result")
	}
}

func TestHdfConvert_HandleRejected(t *testing.T) {
	res, _ := callConvert(t, convertInput{Source: &handle.Source{Handle: "abc"}, From: "gosec"})
	if res == nil || !res.IsError {
		t.Fatal("a handle source must be rejected (convert takes raw output)")
	}
}

func TestHdfConvert_RefuseInvalidResults(t *testing.T) {
	// Directly exercise the schema-invalid refusal (no real converter emits bad
	// output, so this guards the refuse path with hand-crafted invalid HDF).
	if terr := refuseInvalidResults([]byte(`{"baselines":"not-an-array"}`)); terr == nil {
		t.Fatal("schema-invalid output must be refused")
	}
	if terr := refuseInvalidResults(gosecConverted(t)); terr != nil {
		t.Fatalf("valid results must not be refused: %v", terr)
	}
}

// gosecConverted returns a known-valid converted hdf-results document.
func gosecConverted(t *testing.T) []byte {
	t.Helper()
	conv, terr := resolveConverter("gosec", gosecFixture(t))
	if terr != nil {
		t.Fatalf("resolveConverter: %v", terr)
	}
	out, err := conv.Convert(gosecFixture(t))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	return out
}

func TestHdfConvert_ConversionError(t *testing.T) {
	// An XML converter given non-XML input → conversion fails.
	res, _ := callConvert(t, convertInput{Content: "this is not xml at all", From: "nessus"})
	if res == nil || !res.IsError {
		t.Fatal("bad input for the chosen converter must be an isError result")
	}
}

func TestHdfConvert_BothSourceAndContent(t *testing.T) {
	// A mutually-exclusive-argument conflict is a caller mistake: a code-less
	// argError, not the AMBIGUOUS_FORMAT document code (reserved for converter
	// format ties).
	res, _ := callConvert(t, convertInput{Source: &handle.Source{Path: "x"}, Content: "y", From: "gosec"})
	assertArgError(t, res, "either source or content")
}

func TestHdfConvert_PathDenied(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	res, _ := callConvert(t, convertInput{Source: &handle.Source{Path: "../../../etc/passwd"}, From: "gosec"})
	if res == nil || !res.IsError {
		t.Fatal("a path escaping HDF_MCP_ROOT must be denied")
	}
}

func TestHdfConvert_AutoDetect_Undetectable(t *testing.T) {
	res, _ := callConvert(t, convertInput{Content: `{"totally":"unrecognizable","blob":123}`})
	if res == nil || !res.IsError {
		t.Fatal("undetectable input with no from must be an isError result")
	}
}

func TestHdfConvert_SchemaInvalidEndToEnd(t *testing.T) {
	// A non-UUID componentId makes the output fail schema validation → refused,
	// nothing written or handed back.
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	res, out := callConvert(t, convertInput{
		Content: string(awsConfigFixture(t)), From: "aws-config", Output: "out.json",
		ComponentID: "not-a-uuid",
	})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "SCHEMA_INVALID") {
		t.Fatalf("invalid output must be refused with SCHEMA_INVALID: %+v / %s", out, payloadTextOrEmpty(res))
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out.json")); !os.IsNotExist(err) {
		t.Fatal("refused conversion must not write a file")
	}
}

func payloadTextOrEmpty(res *sdkmcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*sdkmcp.TextContent); ok {
		return tc.Text
	}
	return ""
}
