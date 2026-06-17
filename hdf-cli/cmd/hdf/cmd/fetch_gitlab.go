package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	gitlabconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-to-hdf/go"
	gitlab "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/gitlab/go"
)

func newFetchGitlabCmd() *cobra.Command {
	var (
		serverURL       string
		projectID       string
		ref             string
		scanType        string
		artifactPath    string
		jobName         string
		format          string
		maxResponseSize int64
		outputPath      string
	)

	cmd := &cobra.Command{
		Use:   "gitlab [output]",
		Short: "Fetch a GitLab security scan artifact and convert to HDF",
		Long: `Fetch a security report artifact from a GitLab CI/CD pipeline and convert to HDF.

The API token is resolved in this order:
  1. GITLAB_TOKEN environment variable
  2. GLAB_TOKEN environment variable
  3. glab CLI config file (~/.config/glab-cli/config.yml)

Passing credentials as flags is intentionally unsupported to prevent
credential exposure in process lists and shell history.

The --scan-type flag selects the default artifact filename:
  sast                 → gl-sast-report.json
  dast                 → gl-dast-report.json
  dependency-scanning  → gl-dependency-scanning-report.json
  container-scanning   → gl-container-scanning-report.json
  secret-detection     → gl-secret-detection-report.json
  api-fuzzing          → gl-api-fuzzing-report.json

Common GitLab default job names per scan type:
  SAST:                 semgrep-sast
  DAST:                 dast
  Dependency Scanning:  gemnasium-dependency_scanning
  Container Scanning:   container_scanning
  Secret Detection:     secret_detection

Use --artifact-path to override the default filename if your pipeline
uses a custom artifact path.

Use --format raw to skip conversion and save the native GitLab report as-is.

Output defaults to stdout when no output path is given.`,
		Example: `  # Fetch SAST report and convert to HDF
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast output.json

  # Fetch from a specific branch on a self-hosted instance
  hdf fetch gitlab --url https://gitlab.example.com --project 42 \
      --scan-type dast --ref develop --job dast output.json

  # Fetch raw GitLab report without conversion
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast \
      --format raw gl-sast-report.json

  # Write to stdout
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast | jq .`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}

			if err := validateFetchFormat(format); err != nil {
				return err
			}

			// Token is resolved inside the fetcher (env vars + glab config).
			// We check env vars early for a fast user-friendly error, but the
			// fetcher also checks glab config as a fallback.
			if os.Getenv("GITLAB_TOKEN") == "" && os.Getenv("GLAB_TOKEN") == "" {
				printDebug("No GITLAB_TOKEN or GLAB_TOKEN set; will check glab CLI config")
			}

			f, err := gitlab.NewGitLabFetcher(gitlab.GitLabParams{
				URL:             serverURL,
				ProjectID:       projectID,
				Ref:             ref,
				ScanType:        scanType,
				ArtifactPath:    artifactPath,
				JobName:         jobName,
				MaxResponseSize: maxResponseSize,
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize GitLab fetcher: %w", err)
			}

			printDebug("Fetching GitLab %s report for project %s from %s", scanType, projectID, serverURL)
			raw, err := f.Fetch(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to fetch GitLab data: %w", err)
			}
			printDebug("Fetched %d bytes of raw GitLab data", len(raw))

			if format == fetchFormatRaw {
				return writeConvertOutput(raw, outputPath)
			}

			result, err := gitlabconv.ConvertGitlabToHDF(raw, version)
			if err != nil {
				return fmt.Errorf("gitlab conversion failed: %w", err)
			}

			output, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize HDF output: %w", err)
			}

			return writeConvertOutput(output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "https://gitlab.com", "GitLab instance URL")
	cmd.Flags().StringVar(&projectID, "project", "", "Project ID or URL-encoded namespace/project path (required)")
	cmd.Flags().StringVar(&ref, "ref", "main", "Branch or tag name")
	cmd.Flags().StringVar(&scanType, "scan-type", "sast", "Scan type: sast, dast, dependency-scanning, container-scanning, secret-detection, api-fuzzing")
	cmd.Flags().StringVar(&artifactPath, "artifact-path", "", "Override default artifact filename")
	cmd.Flags().StringVar(&jobName, "job", "", "CI job name that produced the artifact (required)")
	cmd.Flags().StringVar(&format, "format", "hdf", "Output format: hdf (convert to HDF) or raw (native GitLab report)")
	cmd.Flags().Int64Var(&maxResponseSize, "max-response-size", 0, "Maximum response size in bytes (default: 10MB, -1 for no limit)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")

	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("job")

	return cmd
}
