package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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

Available sources:
  aws-config    AWS Config compliance evaluation results
  gitlab        GitLab pipeline security scan artifacts
  sonarqube     SonarQube static analysis issues
  splunk        Splunk HDF evaluation events

Examples:
  hdf fetch aws-config --region us-east-1 output.json
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast output.json
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project output.json
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid <guid> output.json`,
	}

	cmd.AddCommand(newFetchAWSConfigCmd())
	cmd.AddCommand(newFetchGitlabCmd())
	cmd.AddCommand(newFetchSonarqubeCmd())
	cmd.AddCommand(newFetchSplunkCmd())

	return cmd
}
