package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"github.com/spf13/cobra"
)

// Global flag variables for query command (used by runQuery).
var (
	queryStatus   []string
	querySeverity []string
	queryImpact   string
	queryCCI      []string
	queryNIST     []string
	querySTIGID   string
	queryTag      []string
	querySearch   string
	queryProfile  string
	queryCount    bool
	queryLimit    int
)

// NewQueryCmd creates a new query command with fresh state.
func NewQueryCmd() *cobra.Command {
	// Local flag variables for this command instance
	var (
		localQueryStatus   []string
		localQuerySeverity []string
		localQueryImpact   string
		localQueryCCI      []string
		localQueryNIST     []string
		localQuerySTIGID   string
		localQueryTag      []string
		localQuerySearch   string
		localQueryProfile  string
		localQueryCount    bool
		localQueryLimit    int
	)

	cmd := &cobra.Command{
		Use:   "query <file>",
		Short: "Search and filter requirements in an HDF document",
		Long: `Search and filter requirements based on status, severity, tags, and text.

Different flags are combined with AND logic. Repeating the same flag
uses OR logic within that filter.

Examples:
  hdf query results.json --status failed
  hdf query results.json --status failed --status not_reviewed
  hdf query results.json --status failed --severity high
  hdf query results.json --severity high --severity critical
  hdf query results.json --cci CCI-000366 --cci CCI-000172
  hdf query results.json --nist "AC-2" --nist "CM-6*"
  hdf query results.json --id V-230221
  hdf query results.json --tag "severity:high" --tag "severity:critical"
  hdf query results.json --search "password"
  hdf query results.json --impact ">0.5" --status failed
  hdf query results.json --baseline "RHEL9-STIG"
  hdf query results.json --status failed --count`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Sync local flags to global variables for runQuery
			queryStatus = localQueryStatus
			querySeverity = localQuerySeverity
			queryImpact = localQueryImpact
			queryCCI = localQueryCCI
			queryNIST = localQueryNIST
			querySTIGID = localQuerySTIGID
			queryTag = localQueryTag
			querySearch = localQuerySearch
			queryProfile = localQueryProfile
			queryCount = localQueryCount
			queryLimit = localQueryLimit
			files, err := expandGlobs(args)
			if err != nil {
				return err
			}
			if len(files) > 1 {
				return runQueryBulk(cmd, files)
			}
			return runQuery(cmd, args)
		},
	}

	cmd.Flags().StringArrayVarP(&localQueryStatus, "status", "s", nil, "Filter by status (repeatable, OR logic): passed, failed, error, not_applicable, not_reviewed")
	cmd.Flags().StringArrayVar(&localQuerySeverity, "severity", nil, "Filter by severity (repeatable, OR logic): critical, high, medium, low, none")
	cmd.Flags().StringVar(&localQueryImpact, "impact", "", "Filter by impact (e.g., \">0.5\", \">=0.7\", \"0.5\")")
	cmd.Flags().StringArrayVar(&localQueryCCI, "cci", nil, "Filter by CCI identifier (repeatable, OR logic)")
	cmd.Flags().StringArrayVar(&localQueryNIST, "nist", nil, "Filter by NIST control (repeatable, OR logic; supports globs)")
	cmd.Flags().StringVar(&localQuerySTIGID, "id", "", "Filter by requirement ID, STIG ID, GID, or group title")
	cmd.Flags().StringArrayVarP(&localQueryTag, "tag", "t", nil, "Filter by tag key:value (repeatable, OR logic)")
	cmd.Flags().StringVar(&localQuerySearch, "search", "", "Search in title and description")
	cmd.Flags().StringVarP(&localQueryProfile, "baseline", "p", "", "Filter by profile name")
	cmd.Flags().BoolVarP(&localQueryCount, "count", "c", false, "Show only the count of matching requirements")
	cmd.Flags().IntVarP(&localQueryLimit, "limit", "l", 0, "Limit number of results (0 = unlimited)")

	return cmd
}

func runQuery(_ *cobra.Command, args []string) error {
	var filename string
	if len(args) == 0 || args[0] == "-" {
		filename = "-"
	} else {
		filename = args[0]
	}

	data, err := readInputFile(filename)
	if err != nil {
		return err
	}

	if _, typeErr := requireDocumentType(data, []string{"results"}, "hdf query"); typeErr != nil {
		return typeErr
	}

	results, err := parseHDFResults(data)
	if err != nil {
		return fmt.Errorf("failed to parse HDF file: %w", err)
	}

	if queryImpact != "" && !hdfengine.ValidImpactFilter(queryImpact) {
		return fmt.Errorf("invalid --impact filter %q: use a comparison like >0.5, >=0.7, <0.5, or =0", queryImpact)
	}

	// Filtering is delegated to the shared hdf-engine library; the CLI supplies
	// its display-status resolver so the engine stays convention-agnostic.
	matches := hdfengine.Filter(context.Background(), results, hdfengine.Options{
		Status:   queryStatus,
		Severity: querySeverity,
		Impact:   queryImpact,
		CCI:      queryCCI,
		NIST:     queryNIST,
		ID:       querySTIGID,
		Tag:      queryTag,
		Search:   querySearch,
		Baseline: queryProfile,
		Limit:    queryLimit,
		Count:    queryCount,
		StatusOf: determineControlStatus,
	})

	return outputQueryResults(matches)
}

// outputQueryResults formats and prints query results.
func outputQueryResults(matches []hdfengine.Match) error {
	if queryCount {
		if jsonOutput {
			output, _ := json.Marshal(map[string]int{"count": len(matches)})
			fmt.Println(string(output))
		} else {
			fmt.Println(len(matches))
		}
		return nil
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(matches, "", "  ")
		fmt.Println(string(output))
		if len(matches) == 0 {
			return &exitCodeError{code: 1, message: "no matching requirements"}
		}
		return nil
	}

	// Human-readable output
	if len(matches) == 0 {
		fmt.Println("No matching requirements found.")
		return &exitCodeError{code: 1, message: "no matching requirements"}
	}

	if !noHeaders {
		fmt.Printf("Found %d matching requirement(s):\n\n", len(matches))
	}

	tbl := NewTable(
		Column{Header: "ID"},
		Column{Header: "Status"},
		Column{Header: "Severity"},
		Column{Header: "Title"},
	)
	for _, m := range matches {
		title := sanitizeOutput(m.Title)
		if len(title) > 55 { //nolint:mnd // truncate long titles for table display
			title = title[:52] + "..."
		}
		if title == "" {
			title = "(no title)"
		}
		tbl.AddRow(sanitizeOutput(m.ID), m.Status, severityToLabel(m.Severity), title)
	}
	tbl.Render()

	return nil
}

// Severity constants aligned with CVSS 3.x bands normalized to 0-1.
// Bands: 0.9-1.0=critical, 0.7-0.8=high, 0.4-0.6=medium, 0.1-0.3=low, 0.0=none.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityNone     = "none"
)

func severityToLabel(severity string) string {
	switch severity {
	case SeverityCritical:
		return "CRIT"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MED "
	case SeverityLow:
		return "LOW "
	case SeverityNone:
		return "NONE"
	default:
		return "NONE"
	}
}

func runQueryBulk(cmd *cobra.Command, files []string) error {
	return runBulk(files, "query", "queried", func(file string) error {
		return runQuery(cmd, []string{file})
	})
}
