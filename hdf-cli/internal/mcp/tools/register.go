package tools

import (
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterAll installs every HDF MCP tool on the server, sharing one loader (so
// the byte-bounded parsed-document cache is shared across tools). It is passed
// to mcp.Run as the registration hook, which keeps the mcp package free of any
// dependency on this one (mcp never imports tools; the wiring is injected).
func RegisterAll(s *sdkmcp.Server) {
	ldr := loader.New(int(mcpMaxInputSize()), 0, 0)
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
