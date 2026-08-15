package tools

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
)

// A non-notexist read failure (here: permission-denied) must surface only the
// caller-relative path in the client payload — never the absolute confined path
// or the raw *PathError errno string, which would reveal the deployer's
// HDF_MCP_ROOT layout. Mirrors the PATH_DENIED branches' relative-path
// discipline.
func TestResolveSource_ReadFailureRedactsAbsolutePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ignores the 0o000 mode bit, so the file stays readable; the redaction logic is OS-agnostic and covered on unix")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file read permissions")
	}
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	abs := filepath.Join(root, "scan.json")
	if err := os.WriteFile(abs, fixtures.Results.Minimal, 0o000); err != nil { // unreadable
		t.Fatal(err)
	}
	errRes, _ := callOpen(t, openInput{Source: handle.Source{Path: "scan.json"}})
	if errRes == nil || !errRes.IsError {
		t.Fatal("an unreadable file must be an isError result")
	}
	payload := payloadText(t, errRes)
	if strings.Contains(payload, root) || strings.Contains(payload, abs) {
		t.Errorf("client payload leaked the absolute path (%q): %s", root, payload)
	}
	if strings.Contains(payload, "permission denied") {
		t.Errorf("client payload leaked the raw errno string: %s", payload)
	}
	if tr := toolResultPayload(t, errRes); tr.Details["path"] != "scan.json" {
		t.Errorf("client payload path = %v, want the relative scan.json", tr.Details["path"])
	}
}
