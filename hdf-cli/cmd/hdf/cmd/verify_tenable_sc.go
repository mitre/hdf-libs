package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	tenablesc "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/tenable-sc/go"
)

func newVerifyTenableSCCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "tenable-sc",
		Short: "Verify Tenable.SC API keys authenticate against a Tenable.SC server",
		Long: `Send an authenticated GET to /rest/currentUser on the configured
Tenable.SC server. A 200 response means the configured access/secret key
pair is valid; 401/403 means it isn't; other status codes are surfaced
unchanged in the error message.

Both API key values must be set via environment variables.

  export TENABLE_SC_ACCESS_KEY=<your-access-key>
  export TENABLE_SC_SECRET_KEY=<your-secret-key>
  hdf verify tenable-sc --url https://tsc.example.com

Exits 0 on success, non-zero on any verification failure.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("TENABLE_SC_ACCESS_KEY") == "" {
				return fmt.Errorf(
					"TENABLE_SC_ACCESS_KEY environment variable is not set\n" +
						"Set it to your Tenable.SC access key before running this command:\n" +
						"  export TENABLE_SC_ACCESS_KEY=<your-access-key>",
				)
			}
			if os.Getenv("TENABLE_SC_SECRET_KEY") == "" {
				return fmt.Errorf(
					"TENABLE_SC_SECRET_KEY environment variable is not set\n" +
						"Set it to your Tenable.SC secret key before running this command:\n" +
						"  export TENABLE_SC_SECRET_KEY=<your-secret-key>",
				)
			}

			f, err := tenablesc.NewTenableSCFetcher(tenablesc.TenableSCParams{URL: serverURL}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize Tenable.SC fetcher: %w", err)
			}

			printDebug("Verifying Tenable.SC credentials against %s", serverURL)
			if err := f.VerifyCredentials(cmd.Context()); err != nil {
				return fmt.Errorf("tenable.sc credential verification failed: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Tenable.SC credentials verified")
			return nil
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "Tenable.SC server URL (required)")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}
