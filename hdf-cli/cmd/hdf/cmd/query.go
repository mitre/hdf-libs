package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/spf13/cobra"
)

// Global flag variables for query command (used by runQuery).
var (
	queryStatus   string
	querySeverity string
	queryImpact   string
	queryCCI      string
	queryNIST     string
	querySTIGID   string
	queryTag      string
	querySearch   string
	queryProfile  string
	queryCount    bool
	queryLimit    int
)

// NewQueryCmd creates a new query command with fresh state.
func NewQueryCmd() *cobra.Command {
	// Local flag variables for this command instance
	var (
		localQueryStatus   string
		localQuerySeverity string
		localQueryImpact   string
		localQueryCCI      string
		localQueryNIST     string
		localQuerySTIGID   string
		localQueryTag      string
		localQuerySearch   string
		localQueryProfile  string
		localQueryCount    bool
		localQueryLimit    int
	)

	cmd := &cobra.Command{
		Use:   "query <file>",
		Short: "Search and filter requirements in an HDF document",
		Long: `Search and filter requirements based on status, severity, tags, and text.

Filters can be combined (AND logic). Use multiple flags to narrow results.

Examples:
  hdf query results.json --status failed
  hdf query results.json --status failed --severity high
  hdf query results.json --cci CCI-000366
  hdf query results.json --nist "AC-2"
  hdf query results.json --id V-230221
  hdf query results.json --tag "severity:high"
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

	cmd.Flags().StringVarP(&localQueryStatus, "status", "s", "", "Filter by status (passed, failed, error, not_applicable, not_reviewed)")
	cmd.Flags().StringVar(&localQuerySeverity, "severity", "", "Filter by severity (high, medium, low, none)")
	cmd.Flags().StringVar(&localQueryImpact, "impact", "", "Filter by impact (e.g., \">0.5\", \">=0.7\", \"0.5\")")
	cmd.Flags().StringVar(&localQueryCCI, "cci", "", "Filter by CCI identifier (e.g., CCI-000366)")
	cmd.Flags().StringVar(&localQueryNIST, "nist", "", "Filter by NIST control (e.g., AC-2, CM-6*)")
	cmd.Flags().StringVar(&localQuerySTIGID, "id", "", "Filter by requirement ID, STIG ID, GID, or group title")
	cmd.Flags().StringVarP(&localQueryTag, "tag", "t", "", "Filter by tag key:value (e.g., severity:high)")
	cmd.Flags().StringVar(&localQuerySearch, "search", "", "Search in title and description")
	cmd.Flags().StringVarP(&localQueryProfile, "baseline", "p", "", "Filter by profile name")
	cmd.Flags().BoolVarP(&localQueryCount, "count", "c", false, "Show only the count of matching requirements")
	cmd.Flags().IntVarP(&localQueryLimit, "limit", "l", 0, "Limit number of results (0 = unlimited)")

	return cmd
}

type queryResult struct {
	ID       string  `json:"id"`
	Title    string  `json:"title,omitempty"`
	Status   string  `json:"status"`
	Impact   float64 `json:"impact"`
	Severity string  `json:"severity"`
	Profile  string  `json:"baseline"`
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

	// Build filter chain and find matches
	filters := buildFilters()
	matches := findMatches(results, filters)

	// Output results
	return outputQueryResults(matches)
}

// findMatches applies filters to all controls and returns matching results.
func findMatches(results hdf.HdfResults, filters []filterFunc) []queryResult {
	var matches []queryResult

	for _, baseline := range results.Baselines {
		// Baseline filter
		if queryProfile != "" && !matchesGlob(baseline.Name, queryProfile) {
			continue
		}

		for _, control := range baseline.Requirements {
			// Check limit (unless counting)
			if queryLimit > 0 && len(matches) >= queryLimit && !queryCount {
				return matches
			}

			status := determineControlStatus(control)
			severity := impactToSeverity(control.Impact)

			// Apply all filters
			if !applyFilters(control, status, severity, filters) {
				continue
			}

			title := ""
			if control.Title != nil {
				title = *control.Title
			}

			matches = append(matches, queryResult{
				ID:       control.ID,
				Title:    title,
				Status:   status,
				Impact:   control.Impact,
				Severity: severity,
				Profile:  baseline.Name,
			})
		}
	}

	return matches
}

// outputQueryResults formats and prints query results.
func outputQueryResults(matches []queryResult) error {
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

type filterFunc func(control hdf.EvaluatedRequirement, status, severity string) bool

func buildFilters() []filterFunc {
	var filters []filterFunc

	// Status filter
	if queryStatus != "" {
		status := strings.ToLower(queryStatus)
		filters = append(filters, func(_ hdf.EvaluatedRequirement, s, _ string) bool {
			return s == status
		})
	}

	// Severity filter
	if querySeverity != "" {
		sev := strings.ToLower(querySeverity)
		filters = append(filters, func(_ hdf.EvaluatedRequirement, _, severity string) bool {
			return severity == sev
		})
	}

	// Impact filter (supports >, >=, <, <=, =)
	if queryImpact != "" {
		op, val := parseImpactFilter(queryImpact)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return compareImpact(c.Impact, op, val)
		})
	}

	// CCI filter
	if queryCCI != "" {
		cci := strings.ToUpper(queryCCI)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return tagContains(c.Tags, "cci", cci)
		})
	}

	// NIST filter
	if queryNIST != "" {
		nist := queryNIST
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			return tagMatchesGlob(c.Tags, "nist", nist)
		})
	}

	// STIG ID filter
	if querySTIGID != "" {
		stigID := querySTIGID
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			// Check multiple possible tag names for STIG ID
			return tagContains(c.Tags, "stig_id", stigID) ||
				tagContains(c.Tags, "gid", stigID) ||
				tagContains(c.Tags, "gtitle", stigID) ||
				c.ID == stigID
		})
	}

	// Generic tag filter (key:value)
	if queryTag != "" {
		parts := strings.SplitN(queryTag, ":", 2)
		if len(parts) == 2 {
			key, value := parts[0], parts[1]
			filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
				return tagMatchesGlob(c.Tags, key, value)
			})
		}
	}

	// Text search filter
	if querySearch != "" {
		search := strings.ToLower(querySearch)
		filters = append(filters, func(c hdf.EvaluatedRequirement, _, _ string) bool {
			// Search in ID
			if strings.Contains(strings.ToLower(c.ID), search) {
				return true
			}
			// Search in title
			if c.Title != nil && strings.Contains(strings.ToLower(*c.Title), search) {
				return true
			}
			// Search in descriptions
			for _, desc := range c.Descriptions {
				if strings.Contains(strings.ToLower(desc.Data), search) {
					return true
				}
			}
			return false
		})
	}

	return filters
}

func applyFilters(control hdf.EvaluatedRequirement, status, severity string, filters []filterFunc) bool {
	for _, f := range filters {
		if !f(control, status, severity) {
			return false
		}
	}
	return true
}

// Severity constants aligned with CVSS 3.x bands normalized to 0-1.
// Bands: 0.9-1.0=critical, 0.7-0.8=high, 0.4-0.6=medium, 0.1-0.3=low, 0.0=informational.
const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityLow           = "low"
	SeverityInformational = "informational"
)

func impactToSeverity(impact float64) string {
	switch {
	case impact >= 0.9:
		return SeverityCritical
	case impact >= 0.7:
		return SeverityHigh
	case impact >= 0.4:
		return SeverityMedium
	case impact > 0:
		return SeverityLow
	default:
		return SeverityInformational
	}
}

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
		return "NONE"
	}
}

func parseImpactFilter(filter string) (string, float64) {
	filter = strings.TrimSpace(filter)

	// Check for operators
	operators := []string{">=", "<=", ">", "<", "="}
	for _, op := range operators {
		if strings.HasPrefix(filter, op) {
			valStr := strings.TrimSpace(filter[len(op):])
			val, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return "=", 0
			}
			return op, val
		}
	}

	// No operator, treat as equality
	val, err := strconv.ParseFloat(filter, 64)
	if err != nil {
		return "=", 0
	}
	return "=", val
}

func compareImpact(impact float64, op string, val float64) bool {
	switch op {
	case ">":
		return impact > val
	case ">=":
		return impact >= val
	case "<":
		return impact < val
	case "<=":
		return impact <= val
	case "=":
		return impact == val
	default:
		return false
	}
}

func tagContains(tags map[string]any, key, value string) bool {
	if tags == nil {
		return false
	}

	tagVal, ok := tags[key]
	if !ok {
		return false
	}

	// Handle different tag value types
	switch v := tagVal.(type) {
	case string:
		return strings.EqualFold(v, value)
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok {
				if strings.EqualFold(str, value) {
					return true
				}
			}
		}
	case []string:
		for _, str := range v {
			if strings.EqualFold(str, value) {
				return true
			}
		}
	}

	return false
}

func tagMatchesGlob(tags map[string]any, key, pattern string) bool {
	if tags == nil {
		return false
	}

	tagVal, ok := tags[key]
	if !ok {
		return false
	}

	// Handle different tag value types with safe regex matching
	switch v := tagVal.(type) {
	case string:
		return safeGlobMatch(v, pattern)
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok {
				if safeGlobMatch(str, pattern) {
					return true
				}
			}
		}
	case []string:
		for _, str := range v {
			if safeGlobMatch(str, pattern) {
				return true
			}
		}
	}

	return false
}

func matchesGlob(s, pattern string) bool {
	return safeGlobMatch(s, pattern)
}

func globToRegex(glob string) string {
	// Escape regex special chars except * and ?
	special := []string{".", "+", "^", "$", "(", ")", "[", "]", "{", "}", "|", "\\"}
	result := glob
	for _, s := range special {
		result = strings.ReplaceAll(result, s, "\\"+s)
	}
	// Convert glob wildcards to regex
	result = strings.ReplaceAll(result, "*", ".*")
	result = strings.ReplaceAll(result, "?", ".")
	return "^" + result + "$"
}

func runQueryBulk(cmd *cobra.Command, files []string) error {
	return runBulk(files, "query", "queried", func(file string) error {
		return runQuery(cmd, []string{file})
	})
}
