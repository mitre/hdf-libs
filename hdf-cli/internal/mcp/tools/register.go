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
	// HDF_MCP_MAX_SIZE parses as int64; clamp to MaxInt32 before narrowing so
	// the value provably fits int on every platform (a math.MaxInt bound is
	// platform-relative and doesn't cover 32-bit builds). 2 GiB comfortably
	// exceeds any sane per-document ceiling (default is 50 MB).
	maxSize := mcpMaxInputSize()
	if maxSize > math.MaxInt32 {
		maxSize = math.MaxInt32
	}
	ldr := loader.New(int(maxSize), 0, 0)
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
