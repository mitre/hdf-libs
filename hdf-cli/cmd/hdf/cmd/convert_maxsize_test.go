package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// A grype input larger than the 50 MiB converter default must convert when the
// user raises --max-size. Before the fix the CLI pre-read passed at --max-size
// but the converter's own guard (a literal 0 = the 50 MiB default) still rejected
// it, so the "use --max-size to increase" advice was a dead end (#334).
func TestConvertCommand_MaxSizeLiftsConverterGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a >50 MiB fixture; skipped under -short")
	}
	// runConvert sets a process-wide configured default; reset it so the raised
	// ceiling never leaks into a later test that relies on the 50 MiB default.
	t.Cleanup(func() { hdfutil.SetDefaultMaxInputSize(0) })

	// Minimal valid grype doc padded past 50 MiB with an ignored descriptor field;
	// the size guard runs before parsing, so the padding need only be valid JSON.
	doc := map[string]any{
		"descriptor": map[string]any{"name": "grype", "padding": strings.Repeat("x", 51*1024*1024)},
		"source":     map[string]any{"target": map[string]any{"userInput": "test"}},
		"matches":    []any{},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= hdfutil.DefaultMaxInputSize {
		t.Fatalf("fixture must exceed the %d-byte default; got %d", hdfutil.DefaultMaxInputSize, len(raw))
	}
	path := filepath.Join(t.TempDir(), "grype-big.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")

	// --max-size 250 admits it at BOTH the CLI pre-read and the converter guard.
	_, stderr, err := executeCommand("convert", "--from", "grype", path, "--max-size", "250", "-o", out)
	if err != nil {
		t.Fatalf("convert with --max-size 250 should succeed on a >50 MiB input, got: %v (stderr: %s)", err, stderr)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("expected output written: %v", statErr)
	}
}

// The XML input guard must honor --max-size too: nessus (and the other XML
// converters) previously stayed capped at 50 MiB regardless of the flag, because
// the XML guard did not consult the configured default (#334).
func TestConvertCommand_MaxSizeLiftsXMLConverterGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a >50 MiB fixture; skipped under -short")
	}
	t.Cleanup(func() { hdfutil.SetDefaultMaxInputSize(0) })

	orig, err := os.ReadFile(converterFixturePath(t, "nessus-to-hdf", "input/sample.nessus"))
	if err != nil {
		t.Fatal(err)
	}
	// Pad past 50 MiB with a prolog XML comment: valid, parser-ignored, and free of
	// entity declarations, so only the size guard is exercised. The guard runs on
	// the raw bytes before parsing.
	pad := []byte("?>\n<!--" + strings.Repeat("x", 51*1024*1024) + "-->")
	raw := bytes.Replace(orig, []byte("?>"), pad, 1)
	if len(raw) <= hdfutil.DefaultMaxInputSize {
		t.Fatalf("padded fixture must exceed the %d-byte default; got %d", hdfutil.DefaultMaxInputSize, len(raw))
	}
	path := filepath.Join(t.TempDir(), "nessus-big.nessus")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")

	_, stderr, err := executeCommand("convert", "--from", "nessus", path, "--max-size", "250", "-o", out)
	if err != nil {
		t.Fatalf("nessus convert with --max-size 250 should succeed on a >50 MiB input, got: %v (stderr: %s)", err, stderr)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("expected output written: %v", statErr)
	}
}
