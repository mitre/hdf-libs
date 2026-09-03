package tools

import (
	"math"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterAll installs every HDF MCP tool on the server, sharing one loader (so
// the byte-bounded parsed-document cache is shared across tools). It is passed
// to mcp.Run as the registration hook, which keeps the mcp package free of any
// dependency on this one (mcp never imports tools; the wiring is injected).
func RegisterAll(s *sdkmcp.Server) {
	// HDF_MCP_MAX_SIZE parses as int64; narrow to int only under a guard
	// proving both bounds, so the value provably fits int on every platform
	// (32-bit included). Out-of-range values fall back to the 2 GiB ceiling,
	// which comfortably exceeds any sane per-document limit (default 50 MB).
	maxSize := math.MaxInt32
	if s := mcpMaxInputSize(); s > 0 && s <= math.MaxInt32 {
		maxSize = int(s)
	}
	ldr := loader.New(maxSize, 0, 0)
	RegisterOpen(s, ldr)
	RegisterInspect(s, ldr)
	RegisterQuery(s, ldr)
	RegisterCompliance(s, ldr)
	RegisterDiff(s, ldr)
	RegisterValidate(s, ldr)
	RegisterConvert(s, ldr)
	RegisterAuthor(s, ldr)
	RegisterApplyAmendment(s, ldr)
}
