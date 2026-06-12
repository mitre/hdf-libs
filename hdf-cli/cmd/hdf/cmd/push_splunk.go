package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	splunk "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/splunk/go"
)

func newPushSplunkCmd() *cobra.Command {
	var (
		serverURL string
		index     string
	)

	cmd := &cobra.Command{
		Use:   "splunk <hdf-input>",
		Short: "Push an HDF Results file to a Splunk index",
		Long: `Convert an HDF Results file to Splunk records (Report / Profile / Control)
and upload them to the configured index. Records carry sourcetype "HDF2Splunk"
to match the Heimdall Splunk dashboard wire format.

The API token must be set via the SPLUNK_TOKEN environment variable.
Passing credentials as flags is intentionally unsupported to prevent
credential exposure in process lists and shell history.

  export SPLUNK_TOKEN=<your-bearer-token>
  hdf push splunk --url https://splunk.example.com --index hdf input.json

Splunk's simple HTTP receiver (` + "`/services/receivers/simple`" + `) is the upload target;
controls are chunked at 100 records per request to match the heimdall2
contract. The target index is verified to exist before any upload occurs.`,
		Example: `  hdf push splunk --url https://splunk.example.com --index hdf results.json

  # Stdin input
  cat results.json | hdf push splunk --url https://splunk.example.com --index hdf -`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := os.Getenv("SPLUNK_TOKEN")
			if token == "" {
				return fmt.Errorf(
					"SPLUNK_TOKEN environment variable is not set\n" +
						"Set it to your Splunk Bearer token before running this command:\n" +
						"  export SPLUNK_TOKEN=<your-bearer-token>",
				)
			}

			if parsed, err := url.Parse(serverURL); err == nil && parsed.Scheme == "http" {
				fmt.Fprintln(os.Stderr, "WARNING: using HTTP; bearer token will be sent in plaintext. Consider using HTTPS.")
			}

			hdfBytes, err := readInputFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read HDF input: %w", err)
			}

			f, err := splunk.NewSplunkFetcher(splunk.SplunkParams{
				URL:   serverURL,
				Index: index,
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize Splunk fetcher: %w", err)
			}

			printDebug("Pushing HDF results to Splunk index %s at %s", index, serverURL)
			if err := f.PushHDF(cmd.Context(), hdfBytes); err != nil {
				return fmt.Errorf("failed to push to Splunk: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Successfully pushed HDF records to Splunk")
			return nil
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "Splunk server URL (required)")
	cmd.Flags().StringVarP(&index, "index", "i", "", "Splunk index to push records into (required)")

	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("index")

	return cmd
}
