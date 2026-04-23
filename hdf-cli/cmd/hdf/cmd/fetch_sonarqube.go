package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mitre/hdf-libs/hdf-cli/internal/fetchers"
	sonarqube "github.com/mitre/hdf-libs/hdf-converters/converters/sonarqube-to-hdf/go"
)

func newFetchSonarqubeCmd() *cobra.Command {
	var (
		serverURL     string
		projectKey    string
		branch        string
		pullRequest   string
		organization  string
		format        string
		outputPath    string
		serverVersion string
	)

	cmd := &cobra.Command{
		Use:   "sonarqube [output]",
		Short: "Fetch SonarQube issues and convert to HDF",
		Long: `Fetch all issues from a SonarQube project and convert them to HDF format.

The API token must be set via the SONARQUBE_TOKEN environment variable.
Passing credentials as flags is intentionally unsupported to prevent
credential exposure in process lists and shell history.

  export SONARQUBE_TOKEN=<your-token>
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project output.json

The server version is auto-detected via /api/server/version and determines
the authentication method (Basic auth for <10, Bearer for 10+). Override
with --sonarqube-version if auto-detection fails.

For SonarCloud, also pass --organization:
  hdf fetch sonarqube --url https://sonarcloud.io --project-key my-project \
      --organization my-org output.json

Output defaults to stdout when no output path is given.`,
		Example: `  # Fetch from a self-hosted SonarQube instance
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project output.json

  # Fetch from a specific branch
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project \
      --branch develop output.json

  # Fetch from a pull request
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project \
      --pull-request 42 output.json

  # Write to stdout
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project | jq .`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}

			if err := validateFetchFormat(format); err != nil {
				return err
			}

			token := os.Getenv("SONARQUBE_TOKEN")
			if token == "" {
				return fmt.Errorf(
					"SONARQUBE_TOKEN environment variable is not set\n" +
						"Set it to your SonarQube API token before running this command:\n" +
						"  export SONARQUBE_TOKEN=<your-token>",
				)
			}

			f, err := fetchers.NewSonarqubeFetcher(fetchers.SonarqubeParams{
				URL:           serverURL,
				ProjectKey:    projectKey,
				Branch:        branch,
				PullRequestID: pullRequest,
				Organization:  organization,
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize SonarQube fetcher: %w", err)
			}
			if serverVersion != "" {
				f.SetServerVersion(serverVersion)
			}

			printDebug("Fetching SonarQube issues for project %s from %s", projectKey, serverURL)
			raw, err := f.Fetch(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to fetch SonarQube data: %w", err)
			}
			printDebug("Fetched %d bytes of raw SonarQube data", len(raw))

			if format == fetchFormatRaw {
				return writeConvertOutput(raw, outputPath)
			}

			result, err := sonarqube.ConvertSonarqubeToHDF(raw, version)
			if err != nil {
				return fmt.Errorf("sonarqube conversion failed: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeConvertOutput(output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "", "SonarQube server URL (required)")
	cmd.Flags().StringVar(&projectKey, "project-key", "", "SonarQube project key (required)")
	cmd.Flags().StringVar(&branch, "branch", "", "Branch name (mutually exclusive with --pull-request)")
	cmd.Flags().StringVar(&pullRequest, "pull-request", "", "Pull request ID (mutually exclusive with --branch)")
	cmd.Flags().StringVar(&organization, "organization", "", "SonarCloud organization key")
	cmd.Flags().StringVar(&format, "format", "hdf", "Output format: hdf (convert to HDF) or raw (native tool output)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&serverVersion, "sonarqube-version", "", "SonarQube server version (auto-detected if omitted; affects auth method)")

	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("project-key")
	cmd.MarkFlagsMutuallyExclusive("branch", "pull-request")

	return cmd
}
