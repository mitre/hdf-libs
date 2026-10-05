package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
)

// Two per-host scans share one file name. Both must be converted and written,
// each output numbered in input order — the same rule the CLI's bulk path
// applies. The number is positional, so the test also pins that every entry
// reports its own outputPath: that is the only place a caller can read the
// number back to the input that produced it.
func TestHdfConvert_Batch_SameBasenameInputsAreNumbered(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/host1/scan.json", gosecFixture(t))
	writeInRootPath(t, "in/host2/scan.json", awsConfigFixture(t))

	res, out := callConvert(t, convertInput{
		Sources:   []handle.Source{{Path: "in/host1/scan.json"}, {Path: "in/host2/scan.json"}},
		OutputDir: "out",
	})
	if res != nil {
		t.Fatalf("same-basename batch must not error: %s", payloadText(t, res))
	}
	entries := asEntries(t, out.Batch)
	if len(entries) != 2 {
		t.Fatalf("expected 2 per-file summaries, got %d: %+v", len(entries), entries)
	}
	// enumerateBatchPaths sorts the batch, so host1 is entry 0 and takes .1.
	want := map[string]string{
		"in/host1/scan.json": "out/scan.1.hdf.json",
		"in/host2/scan.json": "out/scan.2.hdf.json",
	}
	for _, e := range entries {
		if e.Error != "" || e.Code != "" {
			t.Errorf("entry %s failed: %s (%s)", e.InputPath, e.Error, e.Code)
		}
		if e.OutputPath != want[e.InputPath] {
			t.Errorf("%s outputPath = %q, want %q", e.InputPath, e.OutputPath, want[e.InputPath])
		}
		full := filepath.Join(root, filepath.FromSlash(want[e.InputPath]))
		if _, err := os.Stat(full); err != nil {
			t.Errorf("%s was not written: %v", want[e.InputPath], err)
		}
	}
}

// Numbering only applies where it is needed: distinct basenames keep the plain
// <stem>.hdf.json name.
func TestHdfConvert_Batch_DistinctBasenamesKeepPlainNames(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/host1/scan.json", gosecFixture(t))
	writeInRootPath(t, "in/host2/aws.json", awsConfigFixture(t))

	_, out := callConvert(t, convertInput{
		Sources:   []handle.Source{{Path: "in/host1/scan.json"}, {Path: "in/host2/aws.json"}},
		OutputDir: "out",
	})
	got := map[string]string{}
	for _, e := range asEntries(t, out.Batch) {
		got[e.InputPath] = e.OutputPath
	}
	if got["in/host1/scan.json"] != "out/scan.hdf.json" {
		t.Errorf("scan.json outputPath = %q, want out/scan.hdf.json", got["in/host1/scan.json"])
	}
	if got["in/host2/aws.json"] != "out/aws.hdf.json" {
		t.Errorf("aws.json outputPath = %q, want out/aws.hdf.json", got["in/host2/aws.json"])
	}
}

// Numbering must not take a name a literal input already owns: scan.1.json keeps
// out/scan.1.hdf.json and the numbered pair skips that index.
func TestHdfConvert_Batch_NumberingSkipsALiteralName(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/host1/scan.json", gosecFixture(t))
	writeInRootPath(t, "in/host2/scan.json", awsConfigFixture(t))
	writeInRootPath(t, "in/scan.1.json", gosecFixture(t))

	res, out := callConvert(t, convertInput{
		Sources: []handle.Source{
			{Path: "in/host1/scan.json"}, {Path: "in/host2/scan.json"}, {Path: "in/scan.1.json"},
		},
		OutputDir: "out",
	})
	if res != nil {
		t.Fatalf("batch must not error: %s", payloadText(t, res))
	}
	// Sorted batch order: in/host1/scan.json, in/host2/scan.json, in/scan.1.json.
	want := map[string]string{
		"in/host1/scan.json": "out/scan.2.hdf.json",
		"in/host2/scan.json": "out/scan.3.hdf.json",
		"in/scan.1.json":     "out/scan.1.hdf.json",
	}
	seen := map[string]bool{}
	for _, e := range asEntries(t, out.Batch) {
		if e.Error != "" || e.Code != "" {
			t.Errorf("entry %s failed: %s (%s)", e.InputPath, e.Error, e.Code)
		}
		if e.OutputPath != want[e.InputPath] {
			t.Errorf("%s outputPath = %q, want %q", e.InputPath, e.OutputPath, want[e.InputPath])
		}
		if seen[e.OutputPath] {
			t.Errorf("outputPath %q was assigned twice", e.OutputPath)
		}
		seen[e.OutputPath] = true
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(e.OutputPath))); err != nil {
			t.Errorf("%s was not written: %v", e.OutputPath, err)
		}
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct outputs, got %d", len(seen))
	}
}

// The same file named twice is one conversion, as in the CLI: the batch
// enumerator folds the repeat and the single output keeps its plain name.
func TestHdfConvert_Batch_RepeatedInputTolerated(t *testing.T) {
	t.Setenv("HDF_MCP_ROOT", t.TempDir())
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "in/scan.json", gosecFixture(t))

	res, out := callConvert(t, convertInput{
		Sources:   []handle.Source{{Path: "in/scan.json"}, {Path: "./in/scan.json"}},
		OutputDir: "out",
	})
	if res != nil {
		t.Fatalf("a repeated input must not error: %s", payloadText(t, res))
	}
	entries := asEntries(t, out.Batch)
	if len(entries) != 1 {
		t.Fatalf("a repeated input is one conversion, got %d entries: %+v", len(entries), entries)
	}
	if entries[0].OutputPath != "out/scan.hdf.json" {
		t.Errorf("outputPath = %q, want out/scan.hdf.json", entries[0].OutputPath)
	}
}

// A source that names no file has no output name, and that is settled before any
// write or output directory exists.
func TestHdfConvert_Batch_SourceWithoutFileNameRefusedBeforeAnyWrite(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	writeInRootPath(t, "scan.json", gosecFixture(t))

	res, out := callConvert(t, convertInput{
		Sources:   []handle.Source{{Path: "/"}},
		OutputDir: "out",
	})
	if res == nil || !res.IsError {
		t.Fatalf("a source naming no file must be refused, got %+v", out.Batch)
	}
	message, nextCall := argRefusal(t, res)
	if message != `input "/" has no file name to derive an output name from` {
		t.Errorf("message = %q, want the offending input named", message)
	}
	if nextCall != "pass each source as a path ending in a file name" {
		t.Errorf("nextCall = %q, want the remedy", nextCall)
	}
	if len(out.Batch) != 0 {
		t.Errorf("a refused batch must convert nothing, got %d entries", len(out.Batch))
	}
	if _, err := os.Stat(filepath.Join(root, "out")); !os.IsNotExist(err) {
		t.Errorf("the output directory must not be created before the names are known, stat err = %v", err)
	}
}
