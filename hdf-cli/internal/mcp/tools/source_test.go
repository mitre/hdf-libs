package tools

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
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

// The read itself is bounded, independently of the Stat-based guard, so a file
// that delivers more bytes than the ceiling is refused rather than buffered.
func TestReadLimited_RejectsBytesBeyondTheCeiling(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, terr := readLimited(p, "big.json", "source", 32); terr == nil || terr.Code != mcperr.TooLarge {
		t.Fatalf("64 bytes over a 32-byte ceiling must be TOO_LARGE, got %+v", terr)
	}
	content, terr := readLimited(p, "big.json", "source", 64)
	if terr != nil || len(content) != 64 {
		t.Fatalf("64 bytes within a 64-byte ceiling must read whole, got %d bytes / %+v", len(content), terr)
	}
}
