// Package cmd implements the CLI commands for the hdf tool.
package cmd

import (
	"fmt"
	"os"

	hdf "github.com/mitre/hdf-schema"
	validators "github.com/mitre/hdf-validators/go"
	"github.com/spf13/cobra"
)

// Status constants for CLI display output (snake_case for JSON and user-facing text).
const (
	StatusPassed        = "passed"
	StatusFailed        = "failed"
	StatusError         = "error"
	StatusNotApplicable = "not_applicable"
	StatusNotReviewed   = "not_reviewed"
	StatusSkipped       = "skipped" // deprecated in v2, kept for display compatibility
)

// SchemaStatusToDisplay maps HDF schema ResultStatus values (camelCase)
// to CLI display constants (snake_case). This is the single source of truth
// for the schema→CLI status translation.
func SchemaStatusToDisplay(status hdf.ResultStatus) string {
	switch status {
	case hdf.Passed:
		return StatusPassed
	case hdf.Failed:
		return StatusFailed
	case hdf.NotApplicable:
		return StatusNotApplicable
	case hdf.NotReviewed:
		return StatusNotReviewed
	case hdf.Error:
		return StatusError
	default:
		return StatusNotReviewed
	}
}

var (
	// Version information, set at build time.
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// GlobalFlags holds the global command-line flags.
type GlobalFlags struct {
	JSONOutput       bool
	Debug            bool
	MaxSizeMB        int
	NoFollowSymlinks bool
	SchemaDirFlag    string
	ContinueOnError  bool
	NoHeaders        bool
}

// Global flag variables (used by legacy code and helper functions).
var (
	jsonOutput       bool
	debug            bool
	maxSizeMB        int
	noFollowSymlinks bool
	schemaDirFlag    string
	continueOnError  bool
	noHeaders        bool
)

// NewRootCmd creates a new root command with fresh state.
func NewRootCmd() *cobra.Command {
	// Create local flag variables for this command instance
	var gf GlobalFlags

	cmd := &cobra.Command{
		Use:   "hdf",
		Short: "Work with Heimdall Data Format (HDF) files",
		Long: `hdf is a CLI tool for working with Heimdall Data Format (HDF) documents.

HDF is a standardized format for security assessments covering the full
compliance lifecycle: baselines, results, system architecture, assessment
plans, amendments (waivers/attestations), and evidence packages.

Examples:
  hdf validate results.json                 Validate any HDF document
  hdf list results.json                     Summary of what's in a file
  hdf list results.json --detail requirements   List individual requirements
  hdf query results.json --status failed    Filter requirements by status
  hdf convert scan.nessus                   Auto-detect and convert to HDF
  hdf diff old.json new.json                Compare two assessments

For more information: https://github.com/mitre/hdf-libs`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			// Sync local flags to global variables for helper functions
			jsonOutput = gf.JSONOutput
			debug = gf.Debug
			maxSizeMB = gf.MaxSizeMB
			noFollowSymlinks = gf.NoFollowSymlinks
			schemaDirFlag = gf.SchemaDirFlag
			continueOnError = gf.ContinueOnError
			noHeaders = gf.NoHeaders

			initConfig()
		},
	}

	// Global persistent flags
	cmd.PersistentFlags().BoolVar(&gf.JSONOutput, "json", false, "Output in JSON format")
	cmd.PersistentFlags().BoolVarP(&gf.Debug, "debug", "d", false, "Enable debug output")
	cmd.PersistentFlags().IntVar(&gf.MaxSizeMB, "max-size", 50, "Maximum file size in MB")
	cmd.PersistentFlags().BoolVar(&gf.NoFollowSymlinks, "no-follow-symlinks", false, "Refuse to read symlinked files")
	cmd.PersistentFlags().StringVar(&gf.SchemaDirFlag, "schema-dir", "", "Load schemas from directory instead of embedded (for development)")
	cmd.PersistentFlags().BoolVarP(&gf.ContinueOnError, "continue-on-error", "k", false, "Skip files that fail and report errors at the end")
	cmd.PersistentFlags().BoolVar(&gf.NoHeaders, "no-headers", false, "Suppress column headers in table output")

	// Add subcommands
	cmd.AddCommand(NewValidateCmd())
	cmd.AddCommand(NewListCmd())
	cmd.AddCommand(NewQueryCmd())
	cmd.AddCommand(NewConvertCmd())
	cmd.AddCommand(NewDiffCmd())
	cmd.AddCommand(NewAmendCmd())
	cmd.AddCommand(NewEvidenceCmd())
	cmd.AddCommand(NewSystemCmd())
	cmd.AddCommand(NewPlanCmd())
	cmd.AddCommand(NewLabelCmd())
	cmd.AddCommand(NewGenerateCmd())
	cmd.AddCommand(NewFetchCmd())
	cmd.AddCommand(NewVersionCmd())

	return cmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return NewRootCmd().Execute()
}

func initConfig() {
	// Configure schema directory if specified
	if schemaDirFlag != "" {
		validators.SetSchemaDir(schemaDirFlag)
		if debug {
			printDebug("Using schemas from: %s", schemaDirFlag)
		}
	}
}

// printError prints an error message to stderr with optional suggestions.
func printError(msg string, _ ...string) {
	fmt.Fprintln(os.Stderr, "Error:", msg)
}

// printDebug prints debug information if debug mode is enabled.
func printDebug(format string, args ...interface{}) {
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}
