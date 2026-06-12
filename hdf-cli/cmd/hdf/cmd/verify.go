package cmd

import (
	"github.com/spf13/cobra"
)

// NewVerifyCmd creates the `hdf verify` parent command. Each backend ships as
// a subcommand and confirms its credentials are accepted before any further
// fetch/push work runs.
func NewVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <destination>",
		Short: "Verify credentials against a security-tool backend",
		Long: `Probe a backend with the configured credentials and confirm the
authentication round-trip succeeds. Useful in CI scripts before invoking
'hdf fetch' or 'hdf push' so credential failures surface clearly.

TLS options (inherited by all subcommands):
  --ca-cert <path>   PEM CA certificate bundle for custom/corporate CAs
  --insecure         Skip TLS verification (dev/test only, prints warning)

Environment variables: HDF_CA_CERT, HDF_INSECURE=true

Available destinations:
  splunk     Verify SPLUNK_TOKEN authenticates against the server

Examples:
  export SPLUNK_TOKEN=<your-bearer-token>
  hdf verify splunk --url https://splunk.example.com`,
	}

	cmd.PersistentFlags().String("ca-cert", "", "Path to PEM CA certificate bundle for custom/corporate CAs")
	cmd.PersistentFlags().Bool("insecure", false, "Skip TLS certificate verification (prints warning)")

	cmd.AddCommand(newVerifySplunkCmd())

	return cmd
}
