package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mitre/hdf-cli/pkg/amend"
	"github.com/spf13/cobra"
)

// NewAmendCmd creates the amend command group with apply, list, and verify subcommands.
func NewAmendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "amend",
		Short: "Apply, list, or verify HDF amendments",
		Long: `Manage HDF amendments (waivers, attestations, POA&Ms).

Amendments are standalone documents that modify requirement compliance status
in HDF results. Use subcommands to apply, list, or verify amendments.

Examples:
  hdf amend apply results.json waivers.json -o merged.json
  hdf amend list waivers.json
  hdf amend verify waivers.json`,
	}

	cmd.AddCommand(newAmendApplyCmd())
	cmd.AddCommand(newAmendListCmd())
	cmd.AddCommand(newAmendVerifyCmd())

	return cmd
}

func newAmendApplyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply <results-file> <amendments-file>",
		Short: "Apply amendments to an HDF results file",
		Long: `Merge amendments into an HDF results file.

For each override in the amendments, the matching requirement's effectiveStatus
is updated and the override is appended to statusOverrides[]. A previousChecksum
is recorded for chain verification.

Output goes to stdout by default, or to a file with --output.

Examples:
  hdf amend apply results.json waivers.json
  hdf amend apply results.json waivers.json -o merged.json`,
		Args: cobra.ExactArgs(2),
		RunE: runAmendApply,
	}

	cmd.Flags().StringP("output", "o", "", "Write merged output to file instead of stdout")

	return cmd
}

func newAmendListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <amendments-file>",
		Short: "Display overrides in an amendments file",
		Long: `Parse an amendments file and display a table of overrides.

Shows requirement IDs, override types, statuses, expiration dates, and reasons.

Examples:
  hdf amend list waivers.json
  hdf amend list waivers.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: runAmendList,
	}
}

func newAmendVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <amendments-file>",
		Short: "Verify amendment validity and expiration",
		Long: `Check that all overrides in an amendments file have valid, non-expired dates.

Reports the number of valid and expired overrides.

Examples:
  hdf amend verify waivers.json
  hdf amend verify waivers.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: runAmendVerify,
	}
}

func runAmendApply(cmd *cobra.Command, args []string) error {
	resultsPath := args[0]
	amendmentsPath := args[1]

	resultsData, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	amendmentsData, err := os.ReadFile(amendmentsPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read amendments file: %w", err)
	}

	merged, err := amend.MergeAmendments(resultsData, amendmentsData)
	if err != nil {
		return fmt.Errorf("merge failed: %w", err)
	}

	outputPath, _ := cmd.Flags().GetString("output")
	if outputPath != "" {
		// Ensure trailing newline.
		if len(merged) > 0 && merged[len(merged)-1] != '\n' {
			merged = append(merged, '\n')
		}
		if writeErr := os.WriteFile(outputPath, merged, 0o600); writeErr != nil { // #nosec G306 G703 -- CLI intentionally writes to user-provided path
			return fmt.Errorf("failed to write output file: %w", writeErr)
		}
		fmt.Fprintf(os.Stderr, "Merged output written to %s\n", outputPath)
		return nil
	}

	fmt.Println(string(merged))
	return nil
}

func runAmendList(_ *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read amendments file: %w", err)
	}

	name, systemRef, overrides, err := amend.ListOverrides(data)
	if err != nil {
		return err
	}

	if jsonOutput {
		output, marshalErr := json.MarshalIndent(overrides, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to serialize overrides: %w", marshalErr)
		}
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("Amendments: %s\n", name)
	if systemRef != "" {
		fmt.Printf("System: %s\n", systemRef)
	}
	fmt.Println()

	if len(overrides) == 0 {
		fmt.Println("No overrides found.")
		return nil
	}

	fmt.Printf("Overrides (%d):\n", len(overrides))
	for _, ov := range overrides {
		expires := ""
		if ov.ExpiresAt != nil {
			// Truncate to date only for display.
			expires = fmt.Sprintf("Expires: %s", truncateToDate(*ov.ExpiresAt))
		}
		fmt.Printf("  %-8s %-12s %-14s %s   %s\n",
			ov.RequirementID,
			ov.Type,
			ov.Status,
			expires,
			ov.Reason,
		)
	}

	return nil
}

func runAmendVerify(_ *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read amendments file: %w", err)
	}

	result, err := amend.VerifyAmendments(data)
	if err != nil {
		return err
	}

	if jsonOutput {
		output, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to serialize verification result: %w", marshalErr)
		}
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("Total overrides: %d\n", result.TotalOverrides)
	fmt.Printf("Valid:           %d\n", result.ValidOverrides)
	fmt.Printf("Expired:         %d\n", result.ExpiredCount)

	if result.HasErrors {
		fmt.Println("\nWarning: Some overrides are expired or invalid.")
	} else {
		fmt.Println("\nAll overrides are valid.")
	}

	return nil
}

// truncateToDate extracts the date portion from an RFC3339 timestamp string.
// Falls back to the original string if parsing fails.
func truncateToDate(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}
