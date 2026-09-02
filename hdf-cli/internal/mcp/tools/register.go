package tools

import (
	"math"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterAll installs every HDF MCP tool on the server. It is the default
// surface and is passed to mcp.Run as the registration hook.
func RegisterAll(s *sdkmcp.Server) {
	RegisterSelected(s, nil)
}

// RegisterSelected installs only the named tools, sharing one loader (so the
// byte-bounded parsed-document cache is shared across tools). A nil or empty
// names slice installs every tool. Names are expected to be valid — resolve an
// operator-supplied spec through ResolveToolSelection first, which validates and
// orders them; an unrecognized name here is skipped rather than registered.
//
// Keeping the mcp package free of any dependency on this one, the wiring is
// injected: mcp never imports tools.
func RegisterSelected(s *sdkmcp.Server, names []string) {
	// HDF_MCP_MAX_SIZE parses as int64; narrow to int only under a guard proving
	// both bounds, so the value provably fits int on every platform (32-bit
	// included). Out-of-range values fall back to the 2 GiB ceiling, which
	// comfortably exceeds any sane per-document limit (default 50 MB).
	maxSize := math.MaxInt32
	if sz := mcpMaxInputSize(); sz > 0 && sz <= math.MaxInt32 {
		maxSize = int(sz)
	}
	ldr := loader.New(maxSize, 0, 0)
	if len(names) == 0 {
		names = canonicalToolOrder
	}
	for _, name := range names {
		if reg := registrarByName[name]; reg != nil {
			reg(s, ldr)
		}
	}
}
