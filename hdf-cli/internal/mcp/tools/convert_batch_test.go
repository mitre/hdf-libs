package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// asEntry decodes a wire batch entry (map[string]any) back into the typed
// summary for readable assertions. The response carries []map[string]any to keep
// hdf_convert under the per-tool token ceiling (mirrors hdf_query/hdf_diff).
func asEntry(t *testing.T, m map[string]any) fileConvertSummary {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal batch entry: %v", err)
	}
	var e fileConvertSummary
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("decode batch entry: %v", err)
	}
	return e
}

// asEntries decodes the whole batch array for convenience.
func asEntries(t *testing.T, ms []map[string]any) []fileConvertSummary {
	t.Helper()
	out := make([]fileConvertSummary, len(ms))
	for i, m := range ms {
		out[i] = asEntry(t, m)
	}
	return out
}

// writeInRootPath stages a fixture at a (possibly nested) path under
// HDF_MCP_ROOT, creating parent directories as needed.
func writeInRootPath(t *testing.T, rel string, content []byte) {
	t.Helper()
	full := filepath.Join(os.Getenv("HDF_MCP_ROOT"), rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// stageMixedBatch stages a gosec and an aws-config fixture (two different source
// formats, both cleanly auto-detected) under in/ and returns nothing — the batch
// call auto-detects each file's format.
func stageMixedBatch(t *testing.T) {
	t.Helper()
	writeInRootPath(t, "in/scan.json", gosecFixture(t))
	writeInRootPath(t, "in/aws.json", awsConfigFixture(t))
}

func TestHdfConvert_Batch_ConvertsDirectory(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageMixedBatch(t)

	res, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out"})
	if res != nil {
		t.Fatalf("batch convert of valid files must not error: %s", payloadText(t, res))
	}
	if len(out.Batch) != 2 {
		t.Fatalf("expected 2 per-file summaries, got %d: %+v", len(out.Batch), out.Batch)
	}
	entries := asEntries(t, out.Batch)
	// Deterministically ordered by input path: aws.json before scan.json.
	if entries[0].InputPath != "in/aws.json" || entries[1].InputPath != "in/scan.json" {
		t.Fatalf("batch entries not sorted by input path: %+v", entries)
	}
	for _, e := range entries {
		if !e.Valid || e.DocType != "results" {
			t.Errorf("entry %s not a valid results summary: %+v", e.InputPath, e)
		}
		if e.RequirementCount == 0 || e.Handle == "" {
			t.Errorf("entry %s missing reqCount/handle: %+v", e.InputPath, e)
		}
		if e.Error != "" || e.Code != "" {
			t.Errorf("entry %s should have no error: %+v", e.InputPath, e)
		}
	}
	// Each output file is written under the confined out/ dir with the <stem>.hdf.json name.
	for _, name := range []string{"out/aws.hdf.json", "out/scan.hdf.json"} {
		data, err := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), name))
		if err != nil {
			t.Fatalf("expected %s written: %v", name, err)
		}
		if !validators.ValidateResults(data).Valid {
			t.Errorf("%s must validate as hdf-results", name)
		}
	}
	if entries[0].OutputPath != "out/aws.hdf.json" || entries[1].OutputPath != "out/scan.hdf.json" {
		t.Errorf("output paths not derived deterministically: %+v", entries)
	}
}

func TestHdfConvert_Batch_ExplicitSources(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageMixedBatch(t)

	res, out := callConvert(t, convertInput{
		Sources:   []handle.Source{{Path: "in/scan.json"}, {Path: "in/aws.json"}},
		OutputDir: "out",
	})
	if res != nil {
		t.Fatalf("explicit-sources batch must not error: %s", payloadText(t, res))
	}
	if len(out.Batch) != 2 {
		t.Fatalf("expected 2 summaries, got %+v", out.Batch)
	}
	entries := asEntries(t, out.Batch)
	// Sorted regardless of the order the sources were passed in.
	if entries[0].InputPath != "in/aws.json" || entries[1].InputPath != "in/scan.json" {
		t.Fatalf("explicit sources not deterministically ordered: %+v", entries)
	}
}

func TestHdfConvert_Batch_ContinuesPastFailure(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageMixedBatch(t)
	writeInRootPath(t, "in/junk.json", []byte(`{"totally":"unrecognizable"}`))

	res, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out"})
	if res != nil {
		t.Fatalf("continue-past-failure batch must not top-level error: %s", payloadText(t, res))
	}
	if len(out.Batch) != 3 {
		t.Fatalf("expected 3 entries (2 ok + 1 failed), got %+v", out.Batch)
	}
	byPath := map[string]fileConvertSummary{}
	for _, e := range asEntries(t, out.Batch) {
		byPath[e.InputPath] = e
	}
	bad := byPath["in/junk.json"]
	if bad.Valid || bad.Code == "" {
		t.Errorf("unconvertible file must be an error entry with a taxonomy code: %+v", bad)
	}
	// The convertible files still succeeded and were written.
	if !byPath["in/scan.json"].Valid || !byPath["in/aws.json"].Valid {
		t.Errorf("convertible files must still succeed alongside a failure: %+v", out.Batch)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out", "junk.hdf.json")); !os.IsNotExist(err) {
		t.Error("a failed file must not produce an output")
	}
}

func TestHdfConvert_Batch_FailFast(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	// junk sorts first (in/aaa-junk.json), so fail-fast stops before the good files.
	writeInRootPath(t, "in/aaa-junk.json", []byte(`{"totally":"unrecognizable"}`))
	writeInRootPath(t, "in/scan.json", gosecFixture(t))

	res, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out", FailFast: true})
	if res != nil {
		t.Fatalf("fail-fast batch reports failures in entries, not a top-level error: %s", payloadText(t, res))
	}
	if len(out.Batch) != 1 || asEntry(t, out.Batch[0]).Valid {
		t.Fatalf("fail-fast must stop at the first failure: %+v", out.Batch)
	}
}

func TestHdfConvert_Batch_WritesDisabled_SingleNotice(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	stageMixedBatch(t)

	res, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out"})
	if res != nil {
		t.Fatalf("writes-disabled batch is a successful preview, not an error: %s", payloadText(t, res))
	}
	if !out.WritesDisabled {
		t.Errorf("batch must flag writesDisabled: %+v", out)
	}
	// A single batch-level notice, not one per file.
	if out.Notice == "" {
		t.Error("writes-disabled batch must carry a single WRITES_DISABLED notice")
	}
	if len(out.Batch) != 2 {
		t.Fatalf("preview must still summarize every file: %+v", out.Batch)
	}
	for _, e := range asEntries(t, out.Batch) {
		if !e.Valid {
			t.Errorf("preview entry must still be valid: %+v", e)
		}
		if e.OutputPath != "" {
			t.Errorf("writes-disabled must not report a written path: %+v", e)
		}
		if e.Handle == "" {
			t.Errorf("preview entry must still carry a cache-backed handle: %+v", e)
		}
	}
	// No files on disk.
	if entries, _ := os.ReadDir(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out")); len(entries) != 0 {
		t.Errorf("writes-disabled must write no files, found %d", len(entries))
	}
}

func TestHdfConvert_Batch_DryRun(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageMixedBatch(t)

	_, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out", DryRun: true})
	if out.Notice == "" {
		t.Error("dry-run batch must carry a notice")
	}
	if len(out.Batch) != 2 {
		t.Fatalf("dry-run must still summarize every file: %+v", out.Batch)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out")); !os.IsNotExist(err) {
		t.Error("dry-run must not create the output directory contents")
	}
}

// TestHdfConvert_Batch_Deterministic asserts the batch layer's determinism
// guarantee: identical inputs yield the same ordered entries and the same
// input→output path mapping, with no wall-clock or map-iteration order leaking
// in. Per-file byte content is the CONVERTER's determinism property, not the
// batch's: a timestamp-less source (gosec/aws-config) stamps a generation time,
// so its sha256 legitimately varies run-to-run exactly as single-file convert
// does — the batch must not add nondeterminism on top of that, which is what
// this checks.
func TestHdfConvert_Batch_Deterministic(t *testing.T) {
	run := func() convertOutput {
		t.Setenv("HDF_MCP_ROOT", t.TempDir())
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		stageMixedBatch(t)
		_, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out"})
		return out
	}
	a := run()
	b := run()
	if len(a.Batch) != len(b.Batch) {
		t.Fatalf("nondeterministic entry count: %d vs %d", len(a.Batch), len(b.Batch))
	}
	ea, eb := asEntries(t, a.Batch), asEntries(t, b.Batch)
	for i := range ea {
		if ea[i].InputPath != eb[i].InputPath {
			t.Errorf("entry %d ordering differs across runs: %q vs %q", i, ea[i].InputPath, eb[i].InputPath)
		}
		if ea[i].OutputPath != eb[i].OutputPath {
			t.Errorf("entry %d output-path mapping differs across runs: %q vs %q", i, ea[i].OutputPath, eb[i].OutputPath)
		}
	}
}

func TestHdfConvert_Batch_PathDenied(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageMixedBatch(t)

	_, out := callConvert(t, convertInput{
		Sources:   []handle.Source{{Path: "in/scan.json"}, {Path: "../../../etc/passwd"}},
		OutputDir: "out",
	})
	// The escaping source is a PATH_DENIED error entry; the in-root file still converts.
	var denied, ok bool
	for _, e := range asEntries(t, out.Batch) {
		if e.Code == "PATH_DENIED" {
			denied = true
		}
		if e.InputPath == "in/scan.json" && e.Valid {
			ok = true
		}
	}
	if !denied {
		t.Errorf("a source escaping HDF_MCP_ROOT must be a PATH_DENIED entry: %+v", out.Batch)
	}
	if !ok {
		t.Errorf("the in-root file must still convert past the denied one: %+v", out.Batch)
	}
}

func TestHdfConvert_Batch_RejectsMixedSingleAndBatch(t *testing.T) {
	res, _ := callConvert(t, convertInput{
		Content:   string(gosecFixture(t)),
		Directory: "in",
	})
	assertArgError(t, res, "batch")
}

func TestHdfConvert_Batch_HandleRejectedInSources(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	res, _ := callConvert(t, convertInput{
		Sources: []handle.Source{{Handle: "abc"}},
	})
	if res == nil || !res.IsError {
		t.Fatal("a handle in batch sources must be rejected (convert takes raw output)")
	}
}

func TestHdfConvert_Batch_Pattern(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/scan.json", gosecFixture(t))
	writeInRootPath(t, "in/notes.txt", []byte("ignore me"))

	_, out := callConvert(t, convertInput{Directory: "in", Pattern: "*.json", OutputDir: "out"})
	if len(out.Batch) != 1 {
		t.Fatalf("pattern *.json must match only the json file, got %+v", out.Batch)
	}
	if e := asEntry(t, out.Batch[0]); e.InputPath != "in/scan.json" {
		t.Errorf("pattern matched the wrong file: %+v", e)
	}
}

func TestHdfConvert_Batch_InvalidPattern(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	writeInRootPath(t, "in/scan.json", gosecFixture(t))
	res, _ := callConvert(t, convertInput{Directory: "in", Pattern: "[bad"})
	assertArgError(t, res, "pattern")
}

func TestHdfConvert_Batch_NoMatch(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	writeInRootPath(t, "in/scan.json", gosecFixture(t))
	res, _ := callConvert(t, convertInput{Directory: "in", Pattern: "*.nomatch"})
	assertArgError(t, res, "no input files matched")
}

func TestHdfConvert_Batch_EmptySourcePath(t *testing.T) {
	res, _ := callConvert(t, convertInput{Sources: []handle.Source{{}}})
	if res == nil || !res.IsError {
		t.Fatal("a batch source with neither path nor handle must be rejected")
	}
}

func TestHdfConvert_Batch_MissingDirectory(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	res, _ := callConvert(t, convertInput{Directory: "nope"})
	if res == nil || !res.IsError {
		t.Fatal("a nonexistent batch directory must be an error")
	}
}

func TestHdfConvert_Batch_OutputDirDenied(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageMixedBatch(t)
	res, _ := callConvert(t, convertInput{Directory: "in", OutputDir: "../escape"})
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "PATH_DENIED") {
		t.Fatalf("an outputDir escaping HDF_MCP_ROOT must be PATH_DENIED: %s", payloadTextOrEmpty(res))
	}
}

func TestHdfConvert_Batch_WriteFailureEntry(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/scan.json", gosecFixture(t))
	// Pre-create the derived output so the additive write is refused (no overwrite).
	writeInRootPath(t, "out/scan.hdf.json", []byte("existing"))

	_, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out"})
	e := asEntry(t, out.Batch[0])
	// Conversion succeeded (valid), but the write was refused → OUTPUT_EXISTS entry.
	if !e.Valid || e.Code != "OUTPUT_EXISTS" || e.OutputPath != "" {
		t.Fatalf("a refused write must surface OUTPUT_EXISTS while keeping the valid conversion: %+v", e)
	}
	// The existing file is untouched.
	got, _ := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out", "scan.hdf.json"))
	if string(got) != "existing" {
		t.Error("a refused batch write must not clobber the existing file")
	}
}

func TestHdfConvert_Batch_Overwrite(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/scan.json", gosecFixture(t))
	writeInRootPath(t, "out/scan.hdf.json", []byte("stale"))

	_, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out", Overwrite: true})
	e := asEntry(t, out.Batch[0])
	if !e.Valid || e.OutputPath != "out/scan.hdf.json" {
		t.Fatalf("overwrite:true must replace the stale output: %+v", e)
	}
	got, _ := os.ReadFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out", "scan.hdf.json"))
	if !validators.ValidateResults(got).Valid {
		t.Error("overwritten batch output must validate as hdf-results")
	}
}

func TestHdfConvert_Batch_SchemaInvalidPerFile(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/aws.json", awsConfigFixture(t))
	writeInRootPath(t, "in/scan.json", gosecFixture(t))

	// A non-UUID componentId makes the aws-config output fail schema validation;
	// gosec output has no component, so it is unaffected — the batch refuses the
	// invalid file (no output) and still completes the valid one.
	_, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out", ComponentID: "not-a-uuid"})
	byPath := map[string]fileConvertSummary{}
	for _, e := range asEntries(t, out.Batch) {
		byPath[e.InputPath] = e
	}
	if e := byPath["in/aws.json"]; e.Valid || e.Code != "SCHEMA_INVALID" {
		t.Fatalf("schema-invalid output must be refused per file with SCHEMA_INVALID: %+v", e)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HDF_MCP_ROOT"), "out", "aws.hdf.json")); !os.IsNotExist(err) {
		t.Error("a schema-invalid file must not be written")
	}
	if !byPath["in/scan.json"].Valid {
		t.Errorf("the valid file must still convert alongside a schema-invalid one: %+v", byPath["in/scan.json"])
	}
}

func TestHdfConvert_Batch_Truncation(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	// Stage many files so the per-file summary array exceeds the response budget.
	const n = 400
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := "in/" + string(rune('a'+i%26)) + "-" + itoa(i) + ".json"
		writeInRootPath(t, name, gosecFixture(t))
		names = append(names, name)
	}
	sort.Strings(names)

	_, out := callConvert(t, convertInput{Directory: "in", OutputDir: "out"})
	if !out.Truncated {
		t.Fatalf("a batch of %d files must truncate the summary array", n)
	}
	if len(out.Batch) >= n {
		t.Fatalf("truncated batch must drop entries: returned %d of %d", len(out.Batch), n)
	}
	if out.Notice == "" {
		t.Error("a truncated batch must state how many were dropped")
	}
}
