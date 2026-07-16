package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	securitytypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/spf13/cobra"

	securityhubfetcher "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/aws-securityhub/go"
)

func newFetchAWSSecurityHubCmd() *cobra.Command {
	var (
		region     string
		profile    string
		format     string
		outputPath string
		filterJSON string
		check      bool
	)

	cmd := &cobra.Command{
		Use:   "aws-securityhub [output]",
		Short: "Fetch AWS Security Hub findings and convert to HDF",
		Long: `Fetch ASFF findings from AWS Security Hub and convert to HDF format.

Credentials are resolved via the standard AWS credential chain:
  1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables
  2. ~/.aws/credentials and ~/.aws/config (default profile, or --profile)
  3. IAM instance role (EC2/ECS/Lambda)

Use --profile to select a named profile from your AWS CLI configuration.

Use --check to verify credentials without fetching findings — issues a single
DescribeHub call. Exits 0 with "Credentials verified" on stderr when the
configured credentials can reach Security Hub; non-zero otherwise. Useful in
CI scripts that want to bail out early on credential problems.

Output defaults to stdout when no output path is given.`,
		Example: `  # Fetch all Security Hub findings in a region
  hdf fetch aws-securityhub --region us-east-1 output.json

  # Use a named AWS CLI profile
  hdf fetch aws-securityhub --region us-east-1 --profile my-audit-account output.json

  # Save raw ASFF JSON instead of HDF
  hdf fetch aws-securityhub --region us-east-1 --format raw asff.json

  # Narrow the pull with a raw Security Hub filter (e.g. only FAILED findings)
  #   filter.json: {"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}]}
  hdf fetch aws-securityhub --region us-east-1 --filter-json filter.json output.json

  # Verify credentials only (no findings download)
  hdf fetch aws-securityhub --region us-east-1 --check`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}
			if err := validateFetchFormat(format); err != nil {
				return err
			}

			// A raw AwsSecurityFindingFilters JSON document, passed straight to
			// GetFindings. The CLI does not model individual filter fields — the
			// SDK filter surface is large and this covers all of it for the rare
			// case a caller needs to narrow the pull.
			var filters *securitytypes.AwsSecurityFindingFilters
			if filterJSON != "" {
				data, err := os.ReadFile(filterJSON) //nolint:gosec // operator-supplied path
				if err != nil {
					return fmt.Errorf("failed to read --filter-json file: %w", err)
				}
				filters = &securitytypes.AwsSecurityFindingFilters{}
				if err := json.Unmarshal(data, filters); err != nil {
					return fmt.Errorf("invalid --filter-json (expected an ASFF AwsSecurityFindingFilters object): %w", err)
				}
			}

			f, err := securityhubfetcher.NewAWSSecurityHubFetcher(cmd.Context(),
				securityhubfetcher.AWSSecurityHubParams{
					Region:  region,
					Profile: profile,
					TLS:     fetchTLSOptions(cmd),
					Filters: filters,
				})
			if err != nil {
				return fmt.Errorf("failed to initialize AWS Security Hub fetcher: %w", err)
			}

			if check {
				printDebug("Verifying AWS Security Hub credentials in region %s", region)
				if err := f.VerifyCredentials(cmd.Context()); err != nil {
					return fmt.Errorf("aws-securityhub credential verification failed: %w", err)
				}
				fmt.Fprintln(os.Stderr, "AWS Security Hub credentials verified")
				return nil
			}

			printDebug("Fetching AWS Security Hub findings from region %s", region)

			if format == fetchFormatRaw {
				raw, err := f.Fetch(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to fetch AWS Security Hub data: %w", err)
				}
				printDebug("Fetched %d bytes of raw ASFF data", len(raw))
				return writeConvertOutput(raw, outputPath)
			}

			result, err := f.FetchToHDF(cmd.Context(), version)
			if err != nil {
				return fmt.Errorf("failed to fetch AWS Security Hub data: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeValidatedHDFOutput(cmd, output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&region, "region", "r", "", "AWS region (required)")
	cmd.Flags().StringVarP(&profile, "profile", "p", "", "AWS CLI named profile (from ~/.aws/credentials or ~/.aws/config)")
	cmd.Flags().StringVar(&format, "format", "hdf", "Output format: hdf (convert to HDF) or raw (native ASFF JSON)")
	cmd.Flags().StringVar(&filterJSON, "filter-json", "", "Path to a JSON file with an ASFF AwsSecurityFindingFilters object, passed to GetFindings")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().BoolVar(&check, "check", false, "Verify credentials only; skip findings download")
	addNoValidateFlag(cmd)

	_ = cmd.MarkFlagRequired("region")

	return cmd
}
