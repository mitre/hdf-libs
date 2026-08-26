package tools

import (
	"errors"
	"os"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// The shared MCP write model (ADR-0007 §12/§13). Every write tool routes its
// output through writeArtifact so the deployer ceiling (HDF_MCP_ENABLE_WRITES),
// the dry_run preview, and path confinement are implemented once, not per tool.

// writesEnabled reports whether this deployment may write to disk. The ceiling
// defaults to OFF: an unset or non-truthy HDF_MCP_ENABLE_WRITES disables writes.
func writesEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HDF_MCP_ENABLE_WRITES"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Notices returned by writeArtifact for the non-writing outcomes.
const (
	dryRunNotice         = "Dry run: previewed only; no file was written. Re-run without dry_run to write."
	writesDisabledNotice = "WRITES_DISABLED: this deployment cannot write to disk (HDF_MCP_ENABLE_WRITES is unset). Returning a preview; ask the deployer to set HDF_MCP_ENABLE_WRITES=1 to enable writes."
)

// writeArtifact applies the shared write model to a produced document and reports
// what happened. output=="" means no write was requested (pure computation).
// dry_run previews without writing. In a writes-disabled deployment a write
// returns a successful preview with a WRITES_DISABLED notice — never an error,
// since the agent cannot lift the deployer ceiling and an isError would only
// invite a retry loop. Otherwise the document is written to the HDF_MCP_ROOT-
// confined path.
//
// A write is additive by default: it refuses to overwrite an existing file
// (atomic O_EXCL, no TOCTOU) and returns OUTPUT_EXISTS so a caller cannot
// silently destroy in-root data. Passing overwrite replaces the file — the
// opt-in that keeps re-running a pipeline possible. Returns the path actually
// written ("" if none), a notice ("" on a real write and on pure compute), or a
// taxonomy error (PATH_DENIED / OUTPUT_EXISTS / WRITE_FAILED for a filesystem
// failure such as permission-denied or a missing parent directory).
func writeArtifact(output string, dryRun, overwrite bool, data []byte) (writtenPath, notice string, terr *mcperr.Error) {
	if output == "" {
		return "", "", nil
	}
	if dryRun {
		return "", dryRunNotice, nil
	}
	if !writesEnabled() {
		return "", writesDisabledNotice, nil
	}
	confined, err := hdfutil.SafePath(mcpRoot(), output)
	if err != nil {
		return "", "", mcperr.New(mcperr.PathDenied, "output path resolves outside HDF_MCP_ROOT", map[string]any{"path": output})
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL // refuse to clobber an existing file
	}
	f, werr := os.OpenFile(confined, flags, 0o600) //nolint:gosec // confined to HDF_MCP_ROOT by SafePath
	if werr != nil {
		switch {
		case errors.Is(werr, os.ErrExist):
			return "", "", mcperr.New(mcperr.OutputExists, "output path already exists", map[string]any{"path": output})
		case errors.Is(werr, os.ErrNotExist):
			return "", "", mcperr.New(mcperr.WriteFailed, "output directory does not exist", map[string]any{"path": output}).
				WithNextCall("create the parent directory, or choose an `output` path under an existing directory")
		default:
			return "", "", redactFileErr(mcperr.WriteFailed, "could not write output", output, werr)
		}
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return "", "", redactFileErr(mcperr.WriteFailed, "could not write output", output, werr)
	}
	if werr := f.Close(); werr != nil {
		return "", "", redactFileErr(mcperr.WriteFailed, "could not write output", output, werr)
	}
	return output, "", nil
}
