package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	awsconfigconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/aws-config-to-hdf/go"
	awsconfig "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/awsconfig/go"
)

func newFetchAWSConfigCmd() *cobra.Command {
	var (
		region     string
		profile    string
		format     string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "aws-config [output]",
		Short: "Fetch AWS Config compliance data and convert to HDF",
		Long: `Fetch compliance evaluation results from AWS Config and convert to HDF format.

Credentials are resolved via the standard AWS credential chain:
  1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables
  2. ~/.aws/credentials and ~/.aws/config (default profile, or --profile)
  3. IAM instance role (EC2/ECS/Lambda)

Use --profile to select a named profile from your AWS CLI configuration.
This is the recommended approach for users with multiple AWS accounts.

Output defaults to stdout when no output path is given.`,
		Example: `  # Use default credential chain (env vars, default profile, IAM role)
  hdf fetch aws-config --region us-east-1 output.json

  # Use a named AWS CLI profile
  hdf fetch aws-config --region us-east-1 --profile my-audit-account output.json

  # Write to stdout and pipe to jq
  hdf fetch aws-config --region us-east-1 | jq '.baselines[0].requirements | length'`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}

			if err := validateFetchFormat(format); err != nil {
				return err
			}

			f, err := awsconfig.NewAWSConfigFetcher(cmd.Context(), awsconfig.AWSConfigParams{
				Region:  region,
				Profile: profile,
				TLS:     fetchTLSOptions(cmd),
			})
			if err != nil {
				return fmt.Errorf("failed to initialize AWS Config fetcher: %w", err)
			}

			printDebug("Fetching AWS Config rules and evaluation results from region %s", region)
			raw, err := f.Fetch(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to fetch AWS Config data: %w", err)
			}
			printDebug("Fetched %d bytes of raw AWS Config data", len(raw))

			if format == fetchFormatRaw {
				return writeConvertOutput(raw, outputPath)
			}

			result, err := awsconfigconv.ConvertAWSConfigToHDF(raw, version)
			if err != nil {
				return fmt.Errorf("aws-config conversion failed: %w", err)
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
	cmd.Flags().StringVar(&format, "format", "hdf", "Output format: hdf (convert to HDF) or raw (native tool output)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	addNoValidateFlag(cmd)

	_ = cmd.MarkFlagRequired("region")

	return cmd
}
