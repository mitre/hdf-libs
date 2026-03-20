package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newAmendCreateCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "create <results-file>",
		Short: "Interactively create waivers or attestations for failing requirements",
		Long: `Read an HDF results file, present failing requirements for selection,
and generate an hdf-amendments document with the specified overrides.

Requires an interactive terminal. Use hdf amend apply for non-interactive workflows.

Examples:
  hdf amend create results.json -o waivers.json
  hdf amend create results.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runAmendCreate(args[0], outputPath)
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")

	return cmd
}

// failingReq represents a failing requirement for selection.
type failingReq struct {
	ID       string
	Title    string
	Impact   float64
	Baseline string
}

func (r failingReq) String() string {
	return fmt.Sprintf("%-10s %-50s (%.1f) [%s]", r.ID, truncateString(r.Title, 50), r.Impact, r.Baseline)
}

func runAmendCreate(resultsPath, outputPath string) error {
	// Check for interactive terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) { //nolint:gosec // G115: fd conversion is safe for stdin
		return fmt.Errorf("hdf amend create requires an interactive terminal\n" +
			"Use 'hdf amend apply' for non-interactive amendment workflows")
	}

	// Read and parse results
	data, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse results: %w", err)
	}

	// Extract failing requirements
	failing := extractFailingRequirements(doc)
	if len(failing) == 0 {
		fmt.Println("No failing requirements found — nothing to amend.")
		return nil
	}

	fmt.Printf("Found %d failing requirements across all baselines.\n\n", len(failing))

	// Build options for multi-select
	options := make([]huh.Option[string], len(failing))
	for i, r := range failing {
		options[i] = huh.NewOption(r.String(), r.ID)
	}

	// Form variables
	var (
		selectedIDs   []string
		amendType     string
		reason        string
		expiresStr    string
		approverEmail string
	)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select requirements to amend (space to toggle, enter to confirm)").
				Options(options...).
				Value(&selectedIDs),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Amendment type").
				Options(
					huh.NewOption("Waiver — risk accepted", "waiver"),
					huh.NewOption("Attestation — manually verified", "attestation"),
					huh.NewOption("Exception — not applicable", "exception"),
					huh.NewOption("POA&M — remediation planned", "poam"),
				).
				Value(&amendType),
			huh.NewText().
				Title("Reason").
				Placeholder("Explain why this amendment is appropriate...").
				Value(&reason).
				Validate(func(s string) error {
					if len(s) < 5 {
						return fmt.Errorf("reason must be at least 5 characters")
					}
					return nil
				}),
			huh.NewInput().
				Title("Expiration date (YYYY-MM-DD)").
				Placeholder("2026-12-31").
				Value(&expiresStr).
				Validate(func(s string) error {
					_, err := time.Parse("2006-01-02", s)
					if err != nil {
						return fmt.Errorf("invalid date format, use YYYY-MM-DD")
					}
					return nil
				}),
			huh.NewInput().
				Title("Approver email or identifier").
				Placeholder("issm@agency.gov").
				Value(&approverEmail).
				Validate(func(s string) error {
					if len(s) < 3 {
						return fmt.Errorf("approver must be at least 3 characters")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return fmt.Errorf("form cancelled: %w", err)
	}

	if len(selectedIDs) == 0 {
		fmt.Println("No requirements selected — no amendments created.")
		return nil
	}

	// Build amendments document
	amendments := buildAmendmentsDoc(selectedIDs, amendType, reason, expiresStr, approverEmail)

	output, err := json.MarshalIndent(amendments, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize amendments: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil { // #nosec G703 -- CLI writes user path
		return fmt.Errorf("failed to write amendments: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created %s with %d overrides (%s)\n", outputPath, len(selectedIDs), amendType)
	return nil
}

func extractFailingRequirements(doc map[string]interface{}) []failingReq {
	var results []failingReq
	baselines, _ := doc["baselines"].([]interface{})

	for _, bRaw := range baselines {
		b, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}
		baselineName, _ := b["name"].(string)
		reqs, _ := b["requirements"].([]interface{})

		for _, rRaw := range reqs {
			r, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}

			// Check if any result is failed or error
			reqResults, _ := r["results"].([]interface{})
			isFailing := false
			for _, resRaw := range reqResults {
				res, ok := resRaw.(map[string]interface{})
				if !ok {
					continue
				}
				status, _ := res["status"].(string)
				if status == "failed" || status == "error" {
					isFailing = true
					break
				}
			}

			if !isFailing {
				continue
			}

			id, _ := r["id"].(string)
			title := id
			if t, ok := r["title"].(string); ok && t != "" {
				title = t
			}
			impact := 0.5
			if imp, ok := r["impact"].(float64); ok {
				impact = imp
			}

			results = append(results, failingReq{
				ID:       id,
				Title:    title,
				Impact:   impact,
				Baseline: baselineName,
			})
		}
	}
	return results
}

func buildAmendmentsDoc(reqIDs []string, amendType, reason, expiresStr, approver string) map[string]interface{} {
	now := time.Now().UTC().Format(time.RFC3339)
	expiresAt := expiresStr + "T23:59:59Z"

	overrides := make([]map[string]interface{}, len(reqIDs))
	for i, id := range reqIDs {
		overrides[i] = map[string]interface{}{
			"type":          amendType,
			"requirementId": id,
			"status":        amendTypeToStatus(amendType),
			"reason":        reason,
			"appliedBy": map[string]interface{}{
				"type":       "email",
				"identifier": approver,
			},
			"appliedAt": now,
			"expiresAt": expiresAt,
		}
	}

	return map[string]interface{}{
		"name":      fmt.Sprintf("%ss-%s", amendType, time.Now().Format("2006-01-02")),
		"overrides": overrides,
	}
}

func amendTypeToStatus(amendType string) string {
	switch amendType {
	case "waiver", "attestation":
		return "passed"
	case "exception":
		return "notApplicable"
	case "poam":
		return "failed" // POA&M acknowledges the failure, doesn't change status
	default:
		return "notReviewed"
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
