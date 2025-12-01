// Package cmd implements the CLI commands for the hdf tool.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Status constants for control evaluation.
const (
	StatusPassed        = "passed"
	StatusFailed        = "failed"
	StatusError         = "error"
	StatusNotApplicable = "not_applicable"
	StatusNotReviewed   = "not_reviewed"
	StatusSkipped       = "skipped"
)

var (
	// Version information, set at build time.
	version = "dev"
	commit  = "none"
	date    = "unknown"

	// Global flags.
	jsonOutput       bool
	noColor          bool
	debug            bool
	maxSizeMB        int
	noFollowSymlinks bool
)

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
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
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global persistent flags
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug output")
	rootCmd.PersistentFlags().IntVar(&maxSizeMB, "max-size", 50, "Maximum file size in MB")
	rootCmd.PersistentFlags().BoolVar(&noFollowSymlinks, "no-follow-symlinks", false, "Refuse to read symlinked files")
}

func initConfig() {
	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	// Check TERM=dumb
	if os.Getenv("TERM") == "dumb" {
		noColor = true
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
