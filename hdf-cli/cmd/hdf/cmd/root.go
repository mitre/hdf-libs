// Package cmd implements the CLI commands for the hdf tool.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
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

// FilterHelpVocabulary renders the forms a --status/--severity/--disposition flag
// should name, for use in flag help: the canonical vocabulary, then the aliases
// worth teaching, in one parenthesised clause. Built from the engine so a help
// string cannot drift from what the refusal names, and so a retired name stays
// accepted without being advertised.
func FilterHelpVocabulary(field string) string {
	canonical := hdfengine.FilterValues(field)
	if canonical == nil {
		return ""
	}
	taught := make([]string, 0, 2)
	for _, a := range hdfengine.FilterAliases(field) {
		if a.Advertise {
			taught = append(taught, a.Form)
		}
	}
	if len(taught) == 0 {
		return strings.Join(canonical, ", ")
	}
	return fmt.Sprintf("%s (%s also accepted)", strings.Join(canonical, ", "), strings.Join(taught, " and "))
}

// ValidateStatusFilter refuses a --status value outside the engine's closed
// vocabulary, naming the accepted values. Every command taking a status filter
// calls this: a typo that merely matches nothing is indistinguishable from a
// clean run, and `hdf list` and `hdf amend draft` both reported one as an empty
// result with a success exit code.
func ValidateStatusFilter(status string) error {
	if status == "" || hdfengine.ValidStatus(status) {
		return nil
	}
	return fmt.Errorf("unknown --status value %q (expected one of: %s)",
		status, strings.Join(hdfengine.StatusValues, ", "))
}

// StatusFilterMatches reports whether a requirement's status satisfies a status
// filter. BOTH sides go through the engine's alias map, because the two arrive in
// different vocabularies depending on the caller — `hdf list` holds the display
// spelling and `hdf amend draft` the schema one — and a filter must mean the same
// thing on every surface. An empty filter matches everything.
func StatusFilterMatches(filter, status string) bool {
	if filter == "" {
		return true
	}
	return hdfengine.NormalizeFilterValue("status", filter) == hdfengine.NormalizeFilterValue("status", status)
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
	FailFast         bool
	NoHeaders        bool
}

// Global flag variables (used by legacy code and helper functions).
var (
	jsonOutput       bool
	debug            bool
	maxSizeMB        int
	noFollowSymlinks bool
	schemaDirFlag    string
	failFast         bool
	noHeaders        bool
)

// NewRootCmd creates a new root command with fresh state.
func NewRootCmd() *cobra.Command {
	// Create local flag variables for this command instance
	var gf GlobalFlags

	cmd := &cobra.Command{
		Use:     "hdf",
		Version: version,
		Short:   "Work with Heimdall Data Format (HDF) files",
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
			failFast = gf.FailFast
			noHeaders = gf.NoHeaders

			initConfig()
		},
	}

	// Global persistent flags
	cmd.PersistentFlags().BoolVar(&gf.JSONOutput, "json", false, "Output in JSON format")
	cmd.PersistentFlags().BoolVarP(&gf.Debug, "debug", "d", false, "Enable debug output")
	cmd.PersistentFlags().IntVar(&gf.MaxSizeMB, "max-size", 256, "Maximum file size in MB")
	cmd.PersistentFlags().BoolVar(&gf.NoFollowSymlinks, "no-follow-symlinks", false, "Refuse to read symlinked files")
	cmd.PersistentFlags().StringVar(&gf.SchemaDirFlag, "schema-dir", "", "Load schemas from directory instead of embedded (for development)")
	cmd.PersistentFlags().BoolVarP(&gf.FailFast, "fail-fast", "F", false, "Abort on first file that fails instead of continuing")
	cmd.PersistentFlags().BoolVar(&gf.NoHeaders, "no-headers", false, "Suppress column headers in table output")

	// Enable cobra's built-in --version (from the Version field above) and give
	// it the conventional -v shorthand. The output mirrors the `hdf version`
	// subcommand's core string, sharing the same build-time version var.
	cmd.InitDefaultVersionFlag()
	if f := cmd.Flags().Lookup("version"); f != nil {
		f.Shorthand = "v"
	}

	// Add subcommands
	cmd.AddCommand(NewValidateCmd())
	cmd.AddCommand(NewListCmd())
	cmd.AddCommand(NewQueryCmd())
	cmd.AddCommand(NewConvertCmd())
	cmd.AddCommand(NewDiffCmd())
	cmd.AddCommand(NewEventsCmd())
	cmd.AddCommand(NewAmendCmd())
	cmd.AddCommand(NewEnrichCmd())
	cmd.AddCommand(NewEvidenceCmd())
	cmd.AddCommand(NewSystemCmd())
	cmd.AddCommand(NewPlanCmd())
	cmd.AddCommand(NewLabelCmd())
	cmd.AddCommand(NewGenerateCmd())
	cmd.AddCommand(NewFetchCmd())
	cmd.AddCommand(NewMCPCmd())
	cmd.AddCommand(NewVersionCmd())

	markRunErrors(cmd)
	return cmd
}

// Exit codes a command returns by returning an error; main.go turns them into
// the process status through ExitStatus. Diff's POSIX and detailed codes are
// command-local and documented with that command.
const (
	exitUsage       = 2
	exitPartial     = 3
	exitNothingToDo = 4
)

// ExitCoder is implemented by errors that carry a specific process exit code.
// exitCodeError is the only implementation; ExitStatus still falls back to this
// interface so a future one is printed rather than read as a usage error.
type ExitCoder interface {
	error
	ExitCode() int
}

// exitCodeError carries a specific exit code. The command has usually already
// said everything (a diff verdict, a bulk summary, a validation report), so
// main prints no Error line unless report is set.
type exitCodeError struct {
	code    int
	message string
	report  bool
}

func (e *exitCodeError) Error() string { return e.message }
func (e *exitCodeError) ExitCode() int { return e.code }

// runError marks an error as coming from a command's own run, so ExitStatus
// can tell it from the errors Cobra raises before a command runs.
type runError struct{ err error }

func (e *runError) Error() string { return e.err.Error() }
func (e *runError) Unwrap() error { return e.err }

// markRunErrors wraps every RunE in the tree. Cobra has no hook for the
// errors it raises itself (unknown flag or command, arity, a missing required
// flag), so the run side is marked instead and everything unmarked is usage.
func markRunErrors(cmd *cobra.Command) {
	if run := cmd.RunE; run != nil {
		cmd.RunE = func(c *cobra.Command, args []string) error {
			if err := run(c, args); err != nil {
				return &runError{err: err}
			}
			return nil
		}
	}
	for _, sub := range cmd.Commands() {
		markRunErrors(sub)
	}
}

// ExitStatus maps the error Execute returned to a process exit code and says
// whether main should print it: an exit-code error's own code (printed only
// when it asks), 1 for a failed run, 2 for a usage or invocation error.
func ExitStatus(err error) (code int, report bool) {
	var ece *exitCodeError
	if errors.As(err, &ece) {
		return ece.code, ece.report
	}
	var ec ExitCoder
	if errors.As(err, &ec) {
		return ec.ExitCode(), true
	}
	var rf *runError
	if errors.As(err, &rf) {
		return 1, true
	}
	return exitUsage, true
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
