package cmd

import (
	"github.com/spf13/cobra"
)

// NewPushCmd creates the `hdf push` parent command. Each destination (Splunk,
// future: AWS Security Hub) ships as a subcommand.
//
// Inherits the same TLS persistent flags as `hdf fetch` so behavior across
// the two directions is identical.
func NewPushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <destination>",
		Short: "Push HDF data to a security-tool backend",
		Long: `Push HDF Results to a destination backend.

Unlike 'hdf convert', which writes to a local file, 'hdf push' transforms HDF
into the destination's native record shape and uploads it via the destination's
API in one step.

TLS options (inherited by all subcommands):
  --ca-cert <path>   PEM CA certificate bundle for custom/corporate CAs
  --insecure         Skip TLS verification (dev/test only, prints warning)

Environment variables: HDF_CA_CERT, HDF_INSECURE=true

Available destinations:
  splunk     Push HDF as Splunk records (HDF2Splunk dashboard wire format)

Examples:
  export SPLUNK_TOKEN=<your-bearer-token>
  hdf push splunk --url https://splunk.example.com --index hdf input.json

  # Custom CA certificate for internal instances
  hdf push splunk --ca-cert /path/to/internal-ca.pem --url https://splunk.internal ...`,
	}

	// TLS flags inherited from fetch's pattern; persistent so subcommands see them.
	cmd.PersistentFlags().String("ca-cert", "", "Path to PEM CA certificate bundle for custom/corporate CAs")
	cmd.PersistentFlags().Bool("insecure", false, "Skip TLS certificate verification (prints warning)")

	cmd.AddCommand(newPushSplunkCmd())

	return cmd
}
