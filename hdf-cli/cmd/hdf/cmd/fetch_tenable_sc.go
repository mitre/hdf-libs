package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	tenablesc "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/tenable-sc/go"
)

func newFetchTenableSCCmd() *cobra.Command {
	var (
		serverURL  string
		scanID     string
		outputPath string
		format     string
	)

	cmd := &cobra.Command{
		Use:   "tenable-sc [output]",
		Short: "Fetch a Tenable.SC scan result and convert to HDF",
		Long: `Fetch a Tenable.SC scan result via the REST API and convert it to HDF format.
Tenable.SC's downloadType=v2 endpoint returns standard .nessus XML
(either raw or wrapped in a single-entry zip); the fetcher unwraps the
zip transparently and pipes the XML through nessus-to-hdf.

Authentication uses API keys via two environment variables. Passing
credentials as flags is intentionally unsupported to prevent credential
exposure in process lists and shell history.

  export TENABLE_SC_ACCESS_KEY=<your-access-key>
  export TENABLE_SC_SECRET_KEY=<your-secret-key>
  hdf fetch tenable-sc --url https://tsc.example.com --scan-id 42 output.json

Use --format raw to skip conversion and save the unzipped .nessus XML.
Output defaults to stdout when no output path is given.

The --max-size persistent root flag (default 50MB) caps the response
body size to protect against malicious or runaway downloads. Override
with --max-size <MB> if a real scan exceeds this.`,
		Example: `  # Fetch a scan and convert to HDF
  hdf fetch tenable-sc --url https://tsc.example.com --scan-id 42 output.json

  # Save raw .nessus XML instead of HDF
  hdf fetch tenable-sc --url https://tsc.example.com --scan-id 42 --format raw output.nessus

  # Raise the response size cap for a large scan
  hdf --max-size 200 fetch tenable-sc --url https://... --scan-id 42 output.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}
			if err := validateFetchFormat(format); err != nil {
				return err
			}

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

			// Warn if using HTTP — API keys will be sent in plaintext
			if parsed, err := url.Parse(serverURL); err == nil && parsed.Scheme == "http" {
				fmt.Fprintln(os.Stderr, "WARNING: using HTTP; API keys will be sent in plaintext. Consider using HTTPS.")
			}

			f, err := tenablesc.NewTenableSCFetcher(tenablesc.TenableSCParams{
				URL:      serverURL,
				ScanID:   scanID,
				MaxBytes: getMaxFileSize(),
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize Tenable.SC fetcher: %w", err)
			}

			printDebug("Fetching Tenable.SC scan %s from %s", scanID, serverURL)

			if format == fetchFormatRaw {
				raw, err := f.FetchRawScan(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to fetch Tenable.SC scan: %w", err)
				}
				return writeConvertOutput(raw, outputPath)
			}

			result, err := f.FetchScanToHDF(cmd.Context(), version)
			if err != nil {
				return fmt.Errorf("failed to fetch Tenable.SC scan: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeValidatedHDFOutput(cmd, output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "Tenable.SC server URL (required)")
	cmd.Flags().StringVarP(&scanID, "scan-id", "s", "", "Tenable.SC scan result ID (required, positive integer)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVarP(&format, "format", "f", fetchFormatHDF, `Output format: "hdf" (default) or "raw" (unzipped .nessus XML)`)
	addNoValidateFlag(cmd)

	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("scan-id")

	return cmd
}
