package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	splunk "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/splunk/go"
)

func newVerifySplunkCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "splunk",
		Short: "Verify SPLUNK_TOKEN authenticates against a Splunk server",
		Long: `Send an authenticated GET to /services/server/info on the configured
Splunk server. A 200 response means SPLUNK_TOKEN is valid; 401/403 means it
isn't; other status codes are surfaced unchanged in the error message.

The API token must be set via the SPLUNK_TOKEN environment variable.

  export SPLUNK_TOKEN=<your-bearer-token>
  hdf verify splunk --url https://splunk.example.com

Exits 0 on success, non-zero on any verification failure.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("SPLUNK_TOKEN") == "" {
				return fmt.Errorf(
					"SPLUNK_TOKEN environment variable is not set\n" +
						"Set it to your Splunk Bearer token before running this command:\n" +
						"  export SPLUNK_TOKEN=<your-bearer-token>",
				)
			}

			f, err := splunk.NewSplunkFetcher(splunk.SplunkParams{URL: serverURL}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize Splunk fetcher: %w", err)
			}

			printDebug("Verifying SPLUNK_TOKEN against %s", serverURL)
			if err := f.VerifyCredentials(cmd.Context()); err != nil {
				return fmt.Errorf("splunk credential verification failed: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Splunk credentials verified")
			return nil
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "Splunk server URL (required)")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}
