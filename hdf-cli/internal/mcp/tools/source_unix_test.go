//go:build unix

package tools

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
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

// A symlink inside the root to a regular file is still a regular file once
// followed, so the non-regular-file guard must not reject it.
func TestReadFile_SymlinkToRegularFileStillReads(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "real.json"), fixtures.Results.Minimal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.json", filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	errRes, out := callOpen(t, openInput{Source: handle.Source{Path: "link.json"}})
	if errRes != nil && errRes.IsError {
		t.Fatalf("a symlink to a regular file inside the root must read: %s", payloadText(t, errRes))
	}
	if out.DocType != "results" {
		t.Errorf("docType = %q, want results", out.DocType)
	}
}
