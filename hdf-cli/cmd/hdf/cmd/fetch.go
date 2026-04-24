package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/fetchers"
)

// Valid values for the --format flag on fetch subcommands.
const (
	fetchFormatHDF = "hdf"
	fetchFormatRaw = "raw"
)

// validateFetchFormat checks that format is "hdf" or "raw".
func validateFetchFormat(format string) error {
	switch format {
	case fetchFormatHDF, fetchFormatRaw:
		return nil
	default:
		return fmt.Errorf("invalid --format value %q: must be %q or %q", format, fetchFormatHDF, fetchFormatRaw)
	}
}

// fetchTLSOptions reads TLS flags from the command's persistent flags and
// returns a TLSOptions. Falls back to HDF_CA_CERT and HDF_INSECURE env vars.
func fetchTLSOptions(cmd *cobra.Command) fetchers.TLSOptions {
	caCert, _ := cmd.Flags().GetString("ca-cert")
	insecure, _ := cmd.Flags().GetBool("insecure")

	// Environment variable fallback (12-factor pattern).
	if caCert == "" {
		caCert = os.Getenv("HDF_CA_CERT")
	}
	if !insecure && os.Getenv("HDF_INSECURE") == "true" {
		insecure = true
	}

	return fetchers.TLSOptions{
		CACertPath: caCert,
		Insecure:   insecure,
	}
}

// NewFetchCmd creates the fetch command.
// Each source that requires live API access is a subcommand.
func NewFetchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <source>",
		Short: "Fetch security data from a live API and convert to HDF",
		Long: `Fetch data directly from a security tool's API and convert to HDF in one step.

Unlike 'hdf convert', which reads a pre-exported file, 'hdf fetch' connects to
the tool's API at runtime using the credentials you provide and produces HDF output
without any intermediate file.

Use --format raw to skip conversion and save the native tool output as-is.

TLS options (inherited by all subcommands):
  --ca-cert <path>   PEM CA certificate bundle for custom/corporate CAs
  --insecure         Skip TLS verification (dev/test only, prints warning)

Environment variables: HDF_CA_CERT, HDF_INSECURE=true

Available sources:
  aws-config    AWS Config compliance evaluation results
  gitlab        GitLab pipeline security scan artifacts
  sonarqube     SonarQube static analysis issues
  splunk        Splunk HDF evaluation events

Examples:
  hdf fetch aws-config --region us-east-1 output.json
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast output.json
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project output.json
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid <guid> output.json

  # Custom CA certificate for internal instances
  hdf fetch sonarqube --ca-cert /path/to/internal-ca.pem --url https://sonar.internal ...

  # Skip TLS verification (dev/test only)
  hdf fetch gitlab --insecure --url https://gitlab.dev.local ...`,
	}

	// TLS flags are persistent so all subcommands inherit them.
	cmd.PersistentFlags().String("ca-cert", "", "Path to PEM CA certificate bundle for custom/corporate CAs")
	cmd.PersistentFlags().Bool("insecure", false, "Skip TLS certificate verification (prints warning)")

	cmd.AddCommand(newFetchAWSConfigCmd())
	cmd.AddCommand(newFetchGitlabCmd())
	cmd.AddCommand(newFetchSonarqubeCmd())
	cmd.AddCommand(newFetchSplunkCmd())

	return cmd
}
