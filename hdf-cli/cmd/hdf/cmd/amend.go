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
  hdf amend apply --results results.json --amendments waivers.json -o merged.json
  hdf amend list waivers.json
  hdf amend verify waivers.json`,
	}

	cmd.AddCommand(newAmendCreateCmd())
	cmd.AddCommand(newAmendApplyCmd())
	cmd.AddCommand(newAmendListCmd())
	cmd.AddCommand(newAmendVerifyCmd())
	cmd.AddCommand(newAmendSetCmd())

	return cmd
}

func newAmendApplyCmd() *cobra.Command {
	var (
		resultsPath    string
		amendmentsPath string
		outputPath     string
	)

	cmd := &cobra.Command{
		Use:   "apply --results <file> --amendments <file> [-o output]",
		Short: "Apply amendments to an HDF results file",
		Long: `Merge amendments into an HDF results file.

For each override in the amendments, the matching requirement's effectiveStatus
is updated and the override is appended to statusOverrides[]. A previousChecksum
is recorded for chain verification.

Output goes to stdout by default, or to a file with -o/--output.

Examples:
  hdf amend apply --results results.json --amendments waivers.json
  hdf amend apply --results results.json --amendments waivers.json -o merged.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAmendApply(cmd, resultsPath, amendmentsPath, outputPath)
		},
	}

	cmd.Flags().StringVar(&resultsPath, "results", "", "HDF results file to amend (required)")
	cmd.Flags().StringVar(&amendmentsPath, "amendments", "", "Amendments file to apply (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write merged output to file instead of stdout")
	_ = cmd.MarkFlagRequired("results")
	_ = cmd.MarkFlagRequired("amendments")

	return cmd
}

func newAmendListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <amendments-file>",
		Short: "List amendments in an amendments file",
		Long: `Parse an amendments file and display a table of amendments.

Shows requirement IDs, amendment types, statuses, expiration dates, and reasons.

Examples:
  hdf amend list waivers.json
  hdf amend list waivers.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: runAmendList,
	}
}

func newAmendVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <amendments-file> [results-file]",
		Short: "Verify amendment validity, expiration, and chain integrity",
		Long: `Check that all amendments in an amendments file have valid, non-expired dates.

If a results file is also provided, performs full chain verification:
- Verifies previousChecksum matches the SHA-256 of the results document
- Checks that all requirementIds reference actual requirements in the results

Examples:
  hdf amend verify waivers.json                     # Expiration check only
  hdf amend verify waivers.json results.json         # Full chain verification
  hdf amend verify waivers.json results.json --json`,
		Args: cobra.RangeArgs(1, 2),
		RunE: runAmendVerify,
	}
}

func runAmendApply(_ *cobra.Command, resultsPath, amendmentsPath, outputPath string) error {
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

	if _, typeErr := requireDocumentType(data, []string{"amendments"}, "hdf amend list"); typeErr != nil {
		return typeErr
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

	if !noHeaders {
		fmt.Printf("Amendments: %s\n", name)
		if systemRef != "" {
			fmt.Printf("System: %s\n", systemRef)
		}
		fmt.Println()
	}

	if len(overrides) == 0 {
		if !noHeaders {
			fmt.Println("No amendments found.")
		}
		return nil
	}

	if !noHeaders {
		fmt.Printf("Amendments (%d):\n", len(overrides))
	}
	tbl := NewTable(
		Column{Header: "Requirement"},
		Column{Header: "Type"},
		Column{Header: "Status"},
		Column{Header: "Impact"},
		Column{Header: "Expires"},
		Column{Header: "Reason"},
	)
	for _, ov := range overrides {
		expires := ""
		if ov.ExpiresAt != nil {
			expires = truncateToDate(*ov.ExpiresAt)
		}
		impactStr := ""
		if ov.Impact != nil {
			impactStr = fmt.Sprintf("%.1f", *ov.Impact)
		}
		tbl.AddRow(ov.RequirementID, ov.Type, ov.Status, impactStr, expires, ov.Reason)
	}
	tbl.Render()

	return nil
}

func runAmendVerify(_ *cobra.Command, args []string) error {
	amendPath := args[0]

	amendData, err := os.ReadFile(amendPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read amendments file: %w", err)
	}

	if _, typeErr := requireDocumentType(amendData, []string{"amendments"}, "hdf amend verify"); typeErr != nil {
		return typeErr
	}

	// If results file provided, do full chain verification
	if len(args) == 2 {
		return runAmendVerifyChain(amendData, args[1])
	}

	// Otherwise, expiration check only
	result, err := amend.VerifyAmendments(amendData)
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

	fmt.Printf("Total amendments: %d\n", result.TotalOverrides)
	fmt.Printf("Valid:            %d\n", result.ValidOverrides)
	fmt.Printf("Expired:         %d\n", result.ExpiredCount)

	if result.HasErrors {
		fmt.Println("\nWarning: Some amendments are expired or invalid.")
	} else {
		fmt.Println("\nAll amendments are valid.")
	}

	return nil
}

func runAmendVerifyChain(amendData []byte, resultsPath string) error {
	resultsData, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	result, err := amend.VerifyChain(resultsData, amendData)
	if err != nil {
		return err
	}

	if jsonOutput {
		output, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to serialize chain verification: %w", marshalErr)
		}
		fmt.Println(string(output))
		return nil
	}

	// Expiration summary
	exp := result.ExpirationResult
	fmt.Printf("Expiration: %d/%d valid", exp.ValidOverrides, exp.TotalOverrides)
	if exp.ExpiredCount > 0 {
		fmt.Printf(", %d expired", exp.ExpiredCount)
	}
	fmt.Println()

	// Chain verification
	if result.ChainValid {
		fmt.Printf("Chain: \u2713 %s\n", result.ChainMessage)
	} else {
		fmt.Printf("Chain: \u2717 %s\n", result.ChainMessage)
	}

	// Missing requirements
	if len(result.MissingReqIDs) > 0 {
		fmt.Printf("Missing requirements: %v\n", result.MissingReqIDs)
	}

	if !result.ChainValid || exp.HasErrors || len(result.MissingReqIDs) > 0 {
		return fmt.Errorf("verification failed")
	}

	fmt.Println("\nAll checks passed.")
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
