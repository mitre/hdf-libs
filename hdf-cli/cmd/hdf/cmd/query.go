package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"github.com/spf13/cobra"
)

// Global flag variables for query command (used by runQuery).
var (
	queryStatus      []string
	querySeverity    []string
	queryImpact      string
	queryCCI         []string
	queryNIST        []string
	querySTIGID      string
	queryTag         []string
	queryDisposition []string
	queryPoams       string
	querySearch      string
	queryProfile     string
	queryCount       bool
	queryLimit       int
)

// NewQueryCmd creates a new query command with fresh state.
func NewQueryCmd() *cobra.Command {
	// Local flag variables for this command instance
	var (
		localQueryStatus      []string
		localQuerySeverity    []string
		localQueryImpact      string
		localQueryCCI         []string
		localQueryNIST        []string
		localQuerySTIGID      string
		localQueryTag         []string
		localQueryDisposition []string
		localQueryPoams       string
		localQuerySearch      string
		localQueryProfile     string
		localQueryCount       bool
		localQueryLimit       int
	)

	cmd := &cobra.Command{
		Use:   "query <file>",
		Short: "Search and filter requirements in an HDF document",
		Long: `Search and filter requirements based on status, severity, tags, and text.

Different flags are combined with AND logic. Repeating the same flag
uses OR logic within that filter.

--status reports EFFECTIVE status, so a requirement with a governing waiver is
already off "failed" before the filter sees it. --disposition names the type of
the override doing that, and --poams reports whether a remediation plan is still
in force; "none-valid" covers no POA&M, an empty list, and only-lapsed ones
alike, because a plan that has expired is not a plan.

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
  hdf query results.json --disposition waiver --severity critical
  hdf query results.json --status failed --poams none-valid
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
			queryDisposition = localQueryDisposition
			queryPoams = localQueryPoams
			// An unrecognized value would match nothing and report a clean run,
			// which is the false green this vocabulary exists to avoid. Reject it
			// before any document is read.
			if queryPoams != "" && !hdfengine.ValidPoamFilter(queryPoams) {
				return fmt.Errorf("unknown --poams value %q (expected %q or %q)",
					queryPoams, hdfengine.PoamValid, hdfengine.PoamNoneValid)
			}
			for _, status := range queryStatus {
				if !hdfengine.ValidStatus(status) {
					return fmt.Errorf("unknown --status value %q (expected one of: %s)",
						status, strings.Join(hdfengine.StatusValues, ", "))
				}
			}
			for _, severity := range querySeverity {
				if !hdfengine.ValidSeverity(severity) {
					return fmt.Errorf("unknown --severity value %q (expected one of: %s)",
						severity, strings.Join(hdfengine.SeverityValues, ", "))
				}
			}
			for _, disposition := range queryDisposition {
				if !hdfengine.ValidDisposition(disposition) {
					return fmt.Errorf("unknown --disposition value %q (expected one of: %s)",
						disposition, strings.Join(hdfengine.DispositionValues, ", "))
				}
			}
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
	cmd.Flags().StringArrayVar(&localQuerySeverity, "severity", nil, "Filter by severity (repeatable, OR logic): critical, high, medium, low, informational")
	cmd.Flags().StringVar(&localQueryImpact, "impact", "", "Filter by impact (e.g., \">0.5\", \">=0.7\", \"0.5\")")
	cmd.Flags().StringArrayVar(&localQueryCCI, "cci", nil, "Filter by CCI identifier (repeatable, OR logic)")
	cmd.Flags().StringArrayVar(&localQueryNIST, "nist", nil, "Filter by NIST control (repeatable, OR logic; supports globs)")
	cmd.Flags().StringVar(&localQuerySTIGID, "id", "", "Filter by requirement ID, STIG ID, GID, or group title")
	cmd.Flags().StringArrayVarP(&localQueryTag, "tag", "t", nil, "Filter by tag key:value (repeatable, OR logic)")
	cmd.Flags().StringArrayVar(&localQueryDisposition, "disposition", nil,
		"Filter by the governing override's type (repeatable, OR logic): waiver, falsePositive, riskAdjustment, attestation, operationalRequirement, inherited, poam")
	cmd.Flags().StringVar(&localQueryPoams, "poams", "",
		"Filter by remediation-plan validity: valid (a POA&M still in force) or none-valid (none, empty, or only lapsed)")
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
		Status:      queryStatus,
		Severity:    querySeverity,
		Impact:      queryImpact,
		CCI:         queryCCI,
		NIST:        queryNIST,
		ID:          querySTIGID,
		Tag:         queryTag,
		Disposition: queryDisposition,
		Poams:       queryPoams,
		Search:      querySearch,
		Baseline:    queryProfile,
		Limit:       queryLimit,
		Count:       queryCount,
		StatusOf:    determineControlStatus,
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
// Bands: 0.9-1.0=critical, 0.7-0.8=high, 0.4-0.6=medium, 0.1-0.3=low,
// 0.0=informational. The vocabulary is the schema's severity enum, so a filter
// value matches what DeriveSeverity produces.
const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityLow           = "low"
	SeverityInformational = "informational"
	// SeverityNoneLegacy is the pre-3.7 spelling of informational, still
	// accepted as a filter value so an existing command line keeps working.
	SeverityNoneLegacy = "none"
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
	case SeverityInformational:
		return "INFO"
	default:
		return "INFO"
	}
}

func runQueryBulk(cmd *cobra.Command, files []string) error {
	return runBulk(files, "query", "queried", func(file string) error {
		return runQuery(cmd, []string{file})
	})
}
