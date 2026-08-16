package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

func TestGuardFileSize(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "doc.json")
	if err := os.WriteFile(p, make([]byte, 300), 0o600); err != nil {
		t.Fatal(err)
	}
	if terr := guardFileSize(p, "doc.json", "source", 100); terr == nil || terr.Code != mcperr.TooLarge {
		t.Fatalf("300-byte file over a 100 limit must be TOO_LARGE, got %v", terr)
	}
	if terr := guardFileSize(p, "doc.json", "source", 1000); terr != nil {
		t.Fatalf("300-byte file under a 1000 limit must pass, got %v", terr)
	}
	if terr := guardFileSize(filepath.Join(root, "nope.json"), "nope.json", "source", 1000); terr == nil || terr.Code != mcperr.DocumentNotFound {
		t.Fatalf("missing file must be DOCUMENT_NOT_FOUND, got %v", terr)
	}
}

func TestMcpMaxInputSize_Env(t *testing.T) {
	t.Setenv("HDF_MCP_MAX_SIZE", "1234")
	if got := mcpMaxInputSize(); got != 1234 {
		t.Fatalf("env override = %d, want 1234", got)
	}
	t.Setenv("HDF_MCP_MAX_SIZE", "garbage")
	if got := mcpMaxInputSize(); got != int64(hdfutil.DefaultMaxInputSize) {
		t.Fatalf("garbage env must fall back to the default, got %d", got)
	}
	t.Setenv("HDF_MCP_MAX_SIZE", "")
	if got := mcpMaxInputSize(); got != int64(hdfutil.DefaultMaxInputSize) {
		t.Fatalf("unset env must use the default, got %d", got)
	}
}

// TestReadFile_RejectsOversizeBeforeRead proves the pre-read gate: a file over
// HDF_MCP_MAX_SIZE returns TOO_LARGE (via os.Stat) without reading it in.
func TestReadFile_RejectsOversizeBeforeRead(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	t.Setenv("HDF_MCP_MAX_SIZE", "50") // tiny ceiling; any real doc exceeds it
	p := filepath.Join(root, "big.json")
	if err := os.WriteFile(p, []byte(`{"generator":{"name":"x","version":"1"},"baselines":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, terr := readFile(p, "big.json", "source")
	if terr == nil || terr.Code != mcperr.TooLarge {
		t.Fatalf("a file over HDF_MCP_MAX_SIZE must return TOO_LARGE, got %v", terr)
	}
}
