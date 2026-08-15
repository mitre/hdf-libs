package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
)

func TestWriteArtifact_ModelMatrix(t *testing.T) {
	data := []byte(`{"hello":"world"}`)

	t.Run("no output → pure compute, nothing written", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		path, notice, terr := writeArtifact("", false, false, data)
		if terr != nil {
			t.Fatalf("unexpected error: %v", terr)
		}
		if path != "" || notice != "" {
			t.Fatalf("pure compute must write nothing: path=%q notice=%q", path, notice)
		}
	})

	t.Run("dry_run → no write, preview notice", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		path, notice, terr := writeArtifact("out.json", true, false, data)
		if terr != nil {
			t.Fatalf("unexpected error: %v", terr)
		}
		if path != "" {
			t.Fatalf("dry_run must not write, got path %q", path)
		}
		if notice == "" {
			t.Fatal("dry_run must carry a preview notice")
		}
		if _, err := os.Stat(filepath.Join(root, "out.json")); !os.IsNotExist(err) {
			t.Fatal("dry_run must not create a file")
		}
	})

	t.Run("writes disabled → preview + WRITES_DISABLED notice, no error", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "") // disabled (the deployer ceiling default)
		path, notice, terr := writeArtifact("out.json", false, false, data)
		if terr != nil {
			t.Fatalf("writes-disabled must be a successful preview, not an error: %v", terr)
		}
		if path != "" {
			t.Fatalf("writes-disabled must not write, got path %q", path)
		}
		if notice == "" || !contains(notice, "WRITES_DISABLED") {
			t.Fatalf("expected a WRITES_DISABLED notice, got %q", notice)
		}
		if _, err := os.Stat(filepath.Join(root, "out.json")); !os.IsNotExist(err) {
			t.Fatal("writes-disabled must not create a file")
		}
	})

	t.Run("enabled + output → confined write", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "true")
		path, notice, terr := writeArtifact("out.json", false, false, data)
		if terr != nil {
			t.Fatalf("unexpected error: %v", terr)
		}
		if path != "out.json" || notice != "" {
			t.Fatalf("enabled write should return the path with no notice: path=%q notice=%q", path, notice)
		}
		got, err := os.ReadFile(filepath.Join(root, "out.json"))
		if err != nil {
			t.Fatalf("file not written: %v", err)
		}
		if string(got) != string(data) {
			t.Fatalf("written content mismatch: %q", got)
		}
	})

	t.Run("output escaping root → PATH_DENIED", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		_, _, terr := writeArtifact("../escape.json", false, false, data)
		if terr == nil {
			t.Fatal("a path escaping HDF_MCP_ROOT must be denied")
		}
	})

	t.Run("existing output + no overwrite → OUTPUT_EXISTS, file preserved", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		if err := os.WriteFile(filepath.Join(root, "out.json"), []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, terr := writeArtifact("out.json", false, false, data)
		if terr == nil || terr.Code != mcperr.OutputExists {
			t.Fatalf("expected OUTPUT_EXISTS, got %v", terr)
		}
		got, _ := os.ReadFile(filepath.Join(root, "out.json"))
		if string(got) != "original" {
			t.Fatalf("an existing file must not be clobbered, got %q", got)
		}
	})

	t.Run("existing output + overwrite → replaced", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		if err := os.WriteFile(filepath.Join(root, "out.json"), []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		path, _, terr := writeArtifact("out.json", false, true, data)
		if terr != nil {
			t.Fatalf("overwrite must succeed: %v", terr)
		}
		if path != "out.json" {
			t.Fatalf("path = %q, want out.json", path)
		}
		got, _ := os.ReadFile(filepath.Join(root, "out.json"))
		if string(got) != string(data) {
			t.Fatalf("overwrite must replace content, got %q", got)
		}
	})

	// A filesystem write failure is a WRITE_FAILED, not a read-oriented code:
	// permission-denied and missing-parent-directory tell the agent to fix the
	// destination, not to "verify the path exists / call hdf_open".
	t.Run("permission-denied write → WRITE_FAILED", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows ignores the 0o555 dir mode, so the write is not denied; WRITE_FAILED is covered OS-agnostically by the missing-parent-directory subtest")
		}
		if os.Geteuid() == 0 {
			t.Skip("running as root bypasses directory write permissions")
		}
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		if err := os.Mkdir(filepath.Join(root, "ro"), 0o555); err != nil { // read+execute, no write
			t.Fatal(err)
		}
		_, _, terr := writeArtifact("ro/out.json", false, false, data)
		if terr == nil || terr.Code != mcperr.WriteFailed {
			t.Fatalf("expected WRITE_FAILED, got %v", terr)
		}
		if terr.Code == mcperr.DocumentNotFound || terr.Code == mcperr.PathDenied {
			t.Fatalf("write failure must not reuse a read/confinement code, got %s", terr.Code)
		}
		if terr.NextCall == "" {
			t.Fatal("WRITE_FAILED must carry recovery guidance")
		}
		// The client payload must carry only the caller-relative path, never the
		// absolute confined path or the raw errno *PathError string.
		if _, leaked := terr.Details["error"]; leaked {
			t.Errorf("write error must not surface raw err.Error(); details = %v", terr.Details)
		}
		if terr.Details["path"] != "ro/out.json" {
			t.Errorf("client payload path = %v, want the relative ro/out.json", terr.Details["path"])
		}
		if strings.Contains(fmt.Sprint(terr.Details), root) {
			t.Errorf("client payload leaked the absolute root %q: %v", root, terr.Details)
		}
	})

	t.Run("missing parent directory → WRITE_FAILED", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		_, _, terr := writeArtifact("nope/out.json", false, false, data)
		if terr == nil || terr.Code != mcperr.WriteFailed {
			t.Fatalf("expected WRITE_FAILED, got %v", terr)
		}
		if !strings.Contains(terr.Message, "directory") {
			t.Fatalf("a missing-parent failure should say so, got %q", terr.Message)
		}
	})
}

func TestWritesEnabled_TruthyValues(t *testing.T) {
	cases := map[string]bool{"1": true, "true": true, "TRUE": true, "yes": true, "on": true, "": false, "0": false, "false": false, "off": false}
	for v, want := range cases {
		t.Setenv("HDF_MCP_ENABLE_WRITES", v)
		if got := writesEnabled(); got != want {
			t.Errorf("writesEnabled(%q) = %v, want %v", v, got, want)
		}
	}
}
