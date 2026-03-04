package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	"github.com/mitre/hdf-cli/internal/fetchers"
	splunk "github.com/mitre/hdf-converters/converters/splunk-to-hdf/go"
)

func newFetchSplunkCmd() *cobra.Command {
	var (
		serverURL  string
		index      string
		guid       string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "splunk [output]",
		Short: "Fetch Splunk HDF events and convert to HDF",
		Long: `Fetch HDF evaluation events from a Splunk index by GUID and convert them to HDF format.

The API token must be set via the SPLUNK_TOKEN environment variable.
Passing credentials as flags is intentionally unsupported to prevent
credential exposure in process lists and shell history.

  export SPLUNK_TOKEN=<your-bearer-token>
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid <guid> output.json

Output defaults to stdout when no output path is given.`,
		Example: `  # Fetch from a Splunk instance
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid abc123 output.json

  # Write to stdout and pipe to jq
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid abc123 | jq .`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}

			token := os.Getenv("SPLUNK_TOKEN")
			if token == "" {
				return fmt.Errorf(
					"SPLUNK_TOKEN environment variable is not set\n" +
						"Set it to your Splunk Bearer token before running this command:\n" +
						"  export SPLUNK_TOKEN=<your-bearer-token>",
				)
			}

			// Warn if using HTTP — Bearer token will be sent in plaintext
			if parsed, err := url.Parse(serverURL); err == nil && parsed.Scheme == "http" {
				fmt.Fprintln(os.Stderr, "WARNING: using HTTP; bearer token will be sent in plaintext. Consider using HTTPS.")
			}

			f, err := fetchers.NewSplunkFetcher(fetchers.SplunkParams{
				URL:   serverURL,
				Index: index,
				GUID:  guid,
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize Splunk fetcher: %w", err)
			}

			printDebug("Fetching Splunk events for GUID %s from index %s at %s", guid, index, serverURL)
			raw, err := f.Fetch(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to fetch Splunk data: %w", err)
			}
			printDebug("Fetched %d bytes of raw Splunk data", len(raw))

			result, err := splunk.ConvertSplunkToHDF(raw, version)
			if err != nil {
				return fmt.Errorf("splunk conversion failed: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeConvertOutput(output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "Splunk server URL (required)")
	cmd.Flags().StringVarP(&index, "index", "i", "", "Splunk index name (required)")
	cmd.Flags().StringVarP(&guid, "guid", "g", "", "Evaluation GUID to fetch (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")

	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("index")
	_ = cmd.MarkFlagRequired("guid")

	return cmd
}
