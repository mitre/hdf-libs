package cmd

import (
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/resources"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

// NewMCPCmd creates the `hdf mcp` command: a thin entry that runs the MCP server
// over stdio. All server logic lives in internal/mcp — this command only wires
// the transport and passes the build version through.
func NewMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the HDF MCP server (stdio transport)",
		Long: `Run the HDF Model Context Protocol server over stdio.

The server exposes HDF read, analysis, and authoring capabilities to MCP
clients. It speaks JSON-RPC on stdout and must not share stdout with any other
output; logs go to stderr (level via HDF_MCP_LOG_LEVEL).`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mcp.Run(cmd.Context(), version, func(s *sdkmcp.Server) {
				tools.RegisterAll(s)
				resources.RegisterAll(s)
			})
		},
	}
}
