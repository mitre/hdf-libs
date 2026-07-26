package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	defectdojoconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/defectdojo-to-hdf/go"
	defectdojo "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/defectdojo/go"
)

func newFetchDefectDojoCmd() *cobra.Command {
	var (
		serverURL    string
		productName  string
		engagementID string
		testID       string
		format       string
		outputPath   string
		check        bool
	)

	cmd := &cobra.Command{
		Use:   "defectdojo [output]",
		Short: "Fetch DefectDojo findings and convert to HDF",
		Long: `Fetch findings from a DefectDojo instance and convert them to HDF format.

The API token must be set via the DEFECTDOJO_API_TOKEN environment variable.
Passing credentials as flags is intentionally unsupported to prevent
credential exposure in process lists and shell history.

  export DEFECTDOJO_API_TOKEN=<your-token>
  hdf fetch defectdojo --url https://defectdojo.example.com output.json

Findings are grouped into HDF baselines by their underlying scanner (test_type),
and risk-accepted findings carry a full HDF status override (who accepted the
risk, when, why, and when it expires) reconstructed from the finding's inline
risk-acceptance provenance.

Narrow the pull with --product-name, --engagement, or --test.

Use --check to verify the token without downloading findings — issues a single
request to /api/v2/user_profile/. Exits 0 with "Credentials verified" on stderr
when the token is valid; non-zero otherwise.

Output defaults to stdout when no output path is given.`,
		Example: `  # Fetch every finding from an instance
  hdf fetch defectdojo --url https://defectdojo.example.com output.json

  # Fetch findings for a single product
  hdf fetch defectdojo --url https://defectdojo.example.com --product-name "My App" output.json

  # Fetch findings for one engagement
  hdf fetch defectdojo --url https://defectdojo.example.com --engagement 42 output.json

  # Save raw DefectDojo JSON instead of HDF
  hdf fetch defectdojo --url https://defectdojo.example.com --format raw findings.json

  # Verify the token only (no findings download)
  hdf fetch defectdojo --url https://defectdojo.example.com --check`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}
			if err := validateFetchFormat(format); err != nil {
				return err
			}

			if os.Getenv("DEFECTDOJO_API_TOKEN") == "" {
				return fmt.Errorf(
					"DEFECTDOJO_API_TOKEN environment variable is not set\n" +
						"Set it to your DefectDojo API token before running this command:\n" +
						"  export DEFECTDOJO_API_TOKEN=<your-token>",
				)
			}

			f, err := defectdojo.NewDefectDojoFetcher(defectdojo.DefectDojoParams{
				URL:          serverURL,
				ProductName:  productName,
				EngagementID: engagementID,
				TestID:       testID,
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize DefectDojo fetcher: %w", err)
			}

			if check {
				printDebug("Verifying DefectDojo credentials at %s", serverURL)
				if err := f.Verify(cmd.Context()); err != nil {
					return fmt.Errorf("defectdojo credential verification failed: %w", err)
				}
				fmt.Fprintln(os.Stderr, "DefectDojo credentials verified")
				return nil
			}

			printDebug("Fetching DefectDojo findings from %s", serverURL)
			raw, err := f.Fetch(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to fetch DefectDojo data: %w", err)
			}
			printDebug("Fetched %d bytes of raw DefectDojo data", len(raw))

			if format == fetchFormatRaw {
				return writeConvertOutput(raw, outputPath)
			}

			result, err := defectdojoconv.ConvertDefectDojo(raw, version)
			if err != nil {
				return fmt.Errorf("defectdojo conversion failed: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeValidatedHDFOutput(cmd, output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "DefectDojo instance URL (required)")
	cmd.Flags().StringVar(&productName, "product-name", "", "Filter findings to a product by name")
	cmd.Flags().StringVar(&engagementID, "engagement", "", "Filter findings to an engagement by id")
	cmd.Flags().StringVar(&testID, "test", "", "Filter findings to a single test by id")
	cmd.Flags().StringVar(&format, "format", "hdf", "Output format: hdf (convert to HDF) or raw (native tool output)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().BoolVar(&check, "check", false, "Verify credentials only; skip findings download")
	addNoValidateFlag(cmd)

	_ = cmd.MarkFlagRequired("url")

	return cmd
}
