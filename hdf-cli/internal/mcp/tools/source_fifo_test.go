//go:build unix

package tools

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
)

// A FIFO under HDF_MCP_ROOT stats as a zero-byte file, so the size guard alone
// lets the read block forever on a pipe nobody writes. The regular-file check
// must refuse it before any open; the test never opens the FIFO itself.
func TestReadFile_RejectsFIFO(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.json"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	errRes, _ := callOpen(t, openInput{Source: handle.Source{Path: "pipe.json"}})
	if errRes == nil || !errRes.IsError {
		t.Fatal("a FIFO must be refused, never read")
	}
	tr := toolResultPayload(t, errRes)
	if tr.Code != mcperr.DocumentNotFound {
		t.Errorf("code = %q, want %q", tr.Code, mcperr.DocumentNotFound)
	}
	if tr.Details["path"] != "pipe.json" {
		t.Errorf("details path = %v, want the relative pipe.json", tr.Details["path"])
	}
	if strings.Contains(payloadText(t, errRes), root) {
		t.Errorf("client payload leaked the absolute root: %s", payloadText(t, errRes))
	}
}
