package cmd

import (
	"os"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/resources"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

// NewMCPCmd creates the `hdf mcp` command: a thin entry that runs the MCP server
// over stdio. All server logic lives in internal/mcp — this command only wires
// the transport, the tool selection, and the build version through.
func NewMCPCmd() *cobra.Command {
	var toolsFlag string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the HDF MCP server (stdio transport)",
		Long: `Run the HDF Model Context Protocol server over stdio.

The server exposes HDF read, analysis, and authoring capabilities to MCP
clients. It speaks JSON-RPC on stdout and must not share stdout with any other
output; logs go to stderr (level via HDF_MCP_LOG_LEVEL).

By default every tool is advertised. To shrink the per-turn schema an agent
carries, advertise only the tools a deployment needs with --tools (or the
HDF_MCP_TOOLS environment variable): a comma-separated list of tool names
(e.g. hdf_open,hdf_query) or a profile — "read" (the read/analysis tools) or
"all" (the default). --tools takes precedence over HDF_MCP_TOOLS.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec, err := mcpToolSpec(cmd)
			if err != nil {
				return err
			}
			names, err := tools.ResolveToolSelection(spec)
			if err != nil {
				return err
			}
			return mcp.Run(cmd.Context(), version, func(s *sdkmcp.Server) {
				tools.RegisterSelected(s, names)
				resources.RegisterAll(s)
			})
		},
	}
	cmd.Flags().StringVar(&toolsFlag, "tools", "",
		`tools to advertise: comma-separated names (hdf_open,hdf_query) or a profile (read|all); default all`)
	return cmd
}

// mcpToolSpec resolves the tool-selection spec for `hdf mcp`: the --tools flag
// when the operator set it, otherwise the HDF_MCP_TOOLS environment variable
// (empty when neither is set — the all-tools default). The flag wins so an
// explicit invocation overrides an inherited environment.
func mcpToolSpec(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("tools") {
		return cmd.Flags().GetString("tools")
	}
	return os.Getenv("HDF_MCP_TOOLS"), nil
}
