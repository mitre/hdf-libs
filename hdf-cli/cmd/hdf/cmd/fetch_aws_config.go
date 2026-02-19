package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mitre/hdf-cli/internal/fetchers"
	awsconfig "github.com/mitre/hdf-converters/converters/aws-config-to-hdf/go"
)

func newFetchAWSConfigCmd() *cobra.Command {
	var (
		region          string
		accessKeyID     string
		secretAccessKey string
		sessionToken    string
		outputPath      string
	)

	cmd := &cobra.Command{
		Use:   "aws-config [output]",
		Short: "Fetch AWS Config compliance data and convert to HDF",
		Long: `Fetch compliance evaluation results from AWS Config and convert to HDF format.

Credentials are resolved via the standard AWS credential chain:
  1. --access-key-id / --secret-access-key flags
  2. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables
  3. ~/.aws/credentials file
  4. IAM instance role (EC2/ECS/Lambda)

Output defaults to stdout when no output path is given.`,
		Example: `  # IAM role or environment credentials
  hdf fetch aws-config --region us-east-1 output.json

  # Explicit credentials
  hdf fetch aws-config --region us-east-1 \
    --access-key-id YOUR_ACCESS_KEY_ID \
    --secret-access-key YOUR_SECRET_ACCESS_KEY output.json

  # Write to stdout and pipe to jq
  hdf fetch aws-config --region us-east-1 | jq '.baselines[0].requirements | length'`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}

			f, err := fetchers.NewAWSConfigFetcher(cmd.Context(), fetchers.AWSConfigParams{
				Region:          region,
				AccessKeyID:     accessKeyID,
				SecretAccessKey: secretAccessKey,
				SessionToken:    sessionToken,
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

			result, err := awsconfig.ConvertAWSConfigToHDF(raw, version)
			if err != nil {
				return fmt.Errorf("aws-config conversion failed: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeConvertOutput(output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&region, "region", "r", "", "AWS region (required)")
	cmd.Flags().StringVarP(&accessKeyID, "access-key-id", "a", "", "AWS access key ID")
	cmd.Flags().StringVarP(&secretAccessKey, "secret-access-key", "s", "", "AWS secret access key")
	cmd.Flags().StringVarP(&sessionToken, "session-token", "t", "", "AWS session token")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")

	_ = cmd.MarkFlagRequired("region")

	return cmd
}
