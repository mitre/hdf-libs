// Package cmd implements the CLI commands for the hdf tool.
package cmd

import (
	"fmt"
	"os"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
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

// SchemaStatusToDisplay maps HDF v2 schema ResultStatus values (camelCase)
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
	NoColor          bool
	Debug            bool
	MaxSizeMB        int
	NoFollowSymlinks bool
	SchemaDirFlag    string
	Interactive      bool
}

// Global flag variables (used by legacy code and helper functions).
var (
	jsonOutput       bool
	debug            bool
	maxSizeMB        int
	noFollowSymlinks bool
	schemaDirFlag    string
)

// NewRootCmd creates a new root command with fresh state.
func NewRootCmd() *cobra.Command {
	// Create local flag variables for this command instance
	var gf GlobalFlags

	cmd := &cobra.Command{
		Use:   "hdf",
		Short: "Work with Heimdall Data Format (HDF) files",
		Long: `hdf is a CLI tool for working with Heimdall Data Format (HDF) files.

HDF is a standardized format for security assessment results, designed to work
with compliance tools like Chef InSpec, AWS Security Hub, and more.

Examples:
  hdf validate results.json           Validate an HDF results file
  hdf info results.json               Display summary information
  hdf stats results.json              Show assessment statistics
  hdf list controls results.json      List all controls/requirements

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

			initConfig()
		},
	}

	// Global persistent flags
	cmd.PersistentFlags().BoolVar(&gf.JSONOutput, "json", false, "Output in JSON format")
	cmd.PersistentFlags().BoolVar(&gf.NoColor, "no-color", false, "Disable colored output")
	cmd.PersistentFlags().BoolVarP(&gf.Debug, "debug", "d", false, "Enable debug output")
	cmd.PersistentFlags().IntVar(&gf.MaxSizeMB, "max-size", 50, "Maximum file size in MB")
	cmd.PersistentFlags().BoolVar(&gf.NoFollowSymlinks, "no-follow-symlinks", false, "Refuse to read symlinked files")
	cmd.PersistentFlags().StringVar(&gf.SchemaDirFlag, "schema-dir", "", "Load schemas from directory instead of embedded (for development)")
	cmd.PersistentFlags().BoolVarP(&gf.Interactive, "interactive", "i", false, "Launch interactive TUI mode")

	// Add subcommands
	cmd.AddCommand(NewValidateCmd())
	cmd.AddCommand(NewInfoCmd())
	cmd.AddCommand(NewStatsCmd())
	cmd.AddCommand(NewListCmd())
	cmd.AddCommand(NewQueryCmd())
	cmd.AddCommand(NewVersionCmd())
	cmd.AddCommand(NewConvertCmd())
	cmd.AddCommand(NewDiffCmd())
	cmd.AddCommand(NewFetchCmd())
	cmd.AddCommand(NewGenerateCmd())

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
func printError(msg string, suggestions ...string) {
	fmt.Fprintln(os.Stderr, "Error:", msg)
	for _, s := range suggestions {
		fmt.Fprintln(os.Stderr, "  →", s)
	}
}

// printDebug prints debug information if debug mode is enabled.
func printDebug(format string, args ...interface{}) {
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}
