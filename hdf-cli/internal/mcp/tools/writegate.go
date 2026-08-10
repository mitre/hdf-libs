package tools

import (
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
// confined path. Returns the path actually written ("" if none), a notice ("" on
// a real write and on pure compute), or a taxonomy error (only PATH_DENIED / a
// filesystem failure on an enabled write).
func writeArtifact(output string, dryRun bool, data []byte) (writtenPath, notice string, terr *mcperr.Error) {
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
	if werr := os.WriteFile(confined, data, 0o600); werr != nil { //nolint:gosec // confined to HDF_MCP_ROOT by SafePath
		if os.IsNotExist(werr) {
			return "", "", mcperr.New(mcperr.DocumentNotFound, "output directory does not exist", map[string]any{"path": output})
		}
		return "", "", mcperr.New(mcperr.DocumentNotFound, "could not write output", map[string]any{"error": werr.Error()})
	}
	return output, "", nil
}
