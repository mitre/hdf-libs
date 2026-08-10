package tools

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteArtifact_ModelMatrix(t *testing.T) {
	data := []byte(`{"hello":"world"}`)

	t.Run("no output → pure compute, nothing written", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HDF_MCP_ROOT", root)
		t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
		path, notice, terr := writeArtifact("", false, data)
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
		path, notice, terr := writeArtifact("out.json", true, data)
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
		path, notice, terr := writeArtifact("out.json", false, data)
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
		path, notice, terr := writeArtifact("out.json", false, data)
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
		_, _, terr := writeArtifact("../escape.json", false, data)
		if terr == nil {
			t.Fatal("a path escaping HDF_MCP_ROOT must be denied")
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
