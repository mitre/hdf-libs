package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	gitlabvulnconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-vulnerabilities-to-hdf/go"
	gitlabvuln "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/gitlab-vulnerabilities/go"
)

// GitLab's VulnerabilityState and VulnerabilityReportType enums, validated
// here so a typo fails before any request rather than as a GraphQL error.
var (
	gitlabVulnerabilityStates = []string{"DETECTED", "CONFIRMED", "DISMISSED", "RESOLVED"}
	gitlabReportTypes         = []string{
		"SAST", "DEPENDENCY_SCANNING", "CONTAINER_SCANNING", "CONTAINER_SCANNING_FOR_REGISTRY",
		"DAST", "SECRET_DETECTION", "COVERAGE_FUZZING", "API_FUZZING", "CLUSTER_IMAGE_SCANNING", "GENERIC",
	}
)

func newFetchGitlabVulnerabilitiesCmd() *cobra.Command {
	var (
		serverURL        string
		project          string
		group            string
		includeSubgroups bool
		states           string
		reportTypes      string
		format           string
		outputPath       string
		outDir           string
		pageSize         int
		maxPages         int
		maxResponseSize  int64
		check            bool
	)

	cmd := &cobra.Command{
		Use:   "gitlab-vulnerabilities [output]",
		Short: "Fetch a GitLab Vulnerability Report (triage state included) and convert to HDF",
		Long: `Fetch a project's GitLab Vulnerability Report over GraphQL and convert to HDF.

Unlike 'hdf fetch gitlab', which downloads the raw report one CI job wrote,
this reads the deduplicated, persisted, triaged view GitLab maintains from
every scan ingested on the default branch: each finding's state, dismissal
reason and statement, who decided and when, and the full state history.
Dismissals become attributed, expiring HDF overrides; the scanner's raw
result is never rewritten.

The Vulnerability Report is a GitLab Ultimate feature. On Free or Premium
the API answers with an empty list rather than an error, so the fetcher
checks the ingestion signals and refuses to write a document for a report
that was never populated, naming the reason (not Ultimate, scanner job
failed, or no scan has run on the default branch).

The API token is resolved in this order:
  1. GITLAB_TOKEN environment variable
  2. GLAB_TOKEN environment variable
  3. glab CLI config file (~/.config/glab-cli/config.yml)
The token needs read access to the API (read_api, or api) and at least
Developer access to the projects; passing credentials as flags is
intentionally unsupported.

With --group, every non-archived project in the group (subgroups included
by default) is fetched and one HDF file per project is written to --out-dir,
named after the project path with "/" replaced by "__". A project that cannot
be fetched is reported on stderr and the command exits non-zero after the
others are written.

Use --state and --report-type to filter (comma-separated GitLab enum values).
Use --check to run the probe only and print the tier/ingestion diagnosis.
Use --format raw to write the fetched envelope without conversion.

Output defaults to stdout when no output path is given.`,
		Example: `  # One project's triaged findings
  hdf fetch gitlab-vulnerabilities --project my-org/my-project out.json

  # Every project in a group, one HDF per repository
  hdf fetch gitlab-vulnerabilities --group my-org --out-dir ./hdf/

  # Only what is still outstanding
  hdf fetch gitlab-vulnerabilities --project my-org/my-project --state DETECTED,CONFIRMED out.json

  # Only the dismissed set, because the justifications are what is under review
  hdf fetch gitlab-vulnerabilities --project my-org/my-project --state DISMISSED out.json

  # Self-hosted instance, credentials check only
  hdf fetch gitlab-vulnerabilities --url https://gitlab.example.com --project my-org/my-project --check`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" && len(args) > 0 {
				outputPath = args[0]
			}
			if err := validateFetchFormat(format); err != nil {
				return err
			}
			switch {
			case project == "" && group == "":
				return fmt.Errorf("one of --project or --group is required")
			case project != "" && group != "":
				return fmt.Errorf("--project and --group are mutually exclusive")
			case group != "" && outDir == "" && !check:
				return fmt.Errorf("--out-dir is required with --group (one HDF file is written per project)")
			case project != "" && outDir != "":
				return fmt.Errorf("--out-dir applies to --group; use --output or a positional path with --project")
			}
			stateList, err := parseGitlabEnumList(states, "--state", gitlabVulnerabilityStates)
			if err != nil {
				return err
			}
			typeList, err := parseGitlabEnumList(reportTypes, "--report-type", gitlabReportTypes)
			if err != nil {
				return err
			}

			f, err := gitlabvuln.NewGitLabVulnerabilitiesFetcher(gitlabvuln.GitLabVulnerabilitiesParams{
				URL:              serverURL,
				Project:          project,
				Group:            group,
				ExcludeSubgroups: !includeSubgroups,
				States:           stateList,
				ReportTypes:      typeList,
				PageSize:         pageSize,
				MaxPages:         maxPages,
				MaxResponseSize:  maxResponseSize,
			}, fetchTLSOptions(cmd))
			if err != nil {
				return fmt.Errorf("failed to initialize GitLab fetcher: %w", err)
			}

			if check {
				diagnosis, err := f.Verify(cmd.Context())
				if err != nil {
					return fmt.Errorf("GitLab check failed: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), diagnosis.String())
				return nil
			}

			if group != "" {
				return runGitlabVulnerabilitiesGroup(cmd, f, format, outDir)
			}

			printDebug("Fetching GitLab Vulnerability Report for %s from %s", project, serverURL)
			raw, err := f.Fetch(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to fetch GitLab data: %w", err)
			}
			printDebug("Fetched %d bytes", len(raw))
			output, err := renderGitlabVulnerabilities(raw, format)
			if err != nil {
				return err
			}
			if format == fetchFormatRaw {
				return writeConvertOutput(output, outputPath)
			}
			return writeValidatedHDFOutput(cmd, output, outputPath)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "url", "u", "https://gitlab.com", "GitLab instance URL")
	cmd.Flags().StringVar(&project, "project", "", "Project full path (namespace/project)")
	cmd.Flags().StringVar(&group, "group", "", "Group full path; fetches every non-archived project in it")
	cmd.Flags().BoolVar(&includeSubgroups, "include-subgroups", true, "With --group, include projects of subgroups")
	cmd.Flags().StringVar(&states, "state", "", "Comma-separated vulnerability states to fetch: DETECTED, CONFIRMED, DISMISSED, RESOLVED (default: all)")
	cmd.Flags().StringVar(&reportTypes, "report-type", "", "Comma-separated report types to fetch: SAST, DAST, DEPENDENCY_SCANNING, ... (default: all)")
	cmd.Flags().StringVar(&format, "format", "hdf", "Output format: hdf (convert to HDF) or raw (fetched envelope)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path with --project (default: stdout)")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Output directory with --group; one file per project")
	cmd.Flags().IntVar(&pageSize, "page-size", 0, "Findings requested per GraphQL page (default: 25, sized to GitLab's query complexity cap)")
	cmd.Flags().IntVar(&maxPages, "max-pages", 0, "Maximum pages per project, group listing or finding history (default: 500)")
	cmd.Flags().Int64Var(&maxResponseSize, "max-response-size", 0, "Maximum response size in bytes per request (default: 25MB, -1 for no limit)")
	cmd.Flags().BoolVar(&check, "check", false, "Run the probe only and print the tier and ingestion diagnosis")
	addNoValidateFlag(cmd)

	return cmd
}

// parseGitlabEnumList splits a comma list, upper-cases it, and rejects any
// value outside the allowed enum so a typo never reaches the server.
func parseGitlabEnumList(raw, flag string, allowed []string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	for _, v := range strings.Split(raw, ",") {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		ok := false
		for _, a := range allowed {
			if v == a {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("invalid %s value %q: must be one of %s", flag, v, strings.Join(allowed, ", "))
		}
		out = append(out, v)
	}
	return out, nil
}

// renderGitlabVulnerabilities converts the fetched envelope or passes it
// through untouched for --format raw.
func renderGitlabVulnerabilities(raw []byte, format string) ([]byte, error) {
	if format == fetchFormatRaw {
		return raw, nil
	}
	result, err := gitlabvulnconv.ConvertGitlabVulnerabilitiesToHDF(raw, version)
	if err != nil {
		return nil, fmt.Errorf("gitlab-vulnerabilities conversion failed: %w", err)
	}
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}
	return output, nil
}

// runGitlabVulnerabilitiesGroup writes one file per project through the shared
// bulk runner, so a group sweep honours --fail-fast and --json and reports
// failures the same way bulk convert does.
func runGitlabVulnerabilitiesGroup(cmd *cobra.Command, f *gitlabvuln.GitLabVulnerabilitiesFetcher, format, outDir string) error {
	results, err := f.FetchGroup(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to fetch GitLab group: %w", err)
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil { // #nosec G301 -- CLI creates the user-requested directory
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	byPath := make(map[string]gitlabvuln.GroupResult, len(results))
	paths := make([]string, 0, len(results))
	for _, r := range results {
		byPath[r.FullPath] = r
		paths = append(paths, r.FullPath)
	}
	return runBulk(paths, "group fetch", "fetched", func(fullPath string) error {
		r := byPath[fullPath]
		if r.Err != nil {
			return r.Err
		}
		output, err := renderGitlabVulnerabilities(r.Envelope, format)
		if err != nil {
			return err
		}
		target := filepath.Join(outDir, strings.ReplaceAll(fullPath, "/", "__"))
		if format == fetchFormatRaw {
			return writeConvertOutput(output, target+".json")
		}
		return writeValidatedHDFOutput(cmd, output, target+".hdf.json")
	})
}
