package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewPlanCmd creates the plan command group with info subcommand.
func NewPlanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Work with HDF plan documents",
		Long: `Commands for viewing and managing HDF assessment plan documents.

An HDF plan document describes what baselines to run against which targets,
with resolved inputs and scheduling.

Examples:
  hdf plan info quarterly-plan.hdf-plan.json
  hdf plan info quarterly-plan.hdf-plan.json --json`,
	}

	cmd.AddCommand(newPlanInfoCmd())
	cmd.AddCommand(newPlanCreateCmd())
	cmd.AddCommand(newPlanSetCmd())

	return cmd
}

func newPlanInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <file>",
		Short: "Display summary information about an HDF plan document",
		Long: `Display summary information about an HDF plan document including:
- Plan name, type, and system reference
- Assessments with baselines and runners
- Schedule configuration

Examples:
  hdf plan info quarterly-plan.hdf-plan.json
  hdf plan info quarterly-plan.hdf-plan.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDocInfo(args[0], "hdf plan info", []string{"plan"}, outputPlanInfoHuman)
		},
	}
}

func outputPlanInfoHuman(doc map[string]interface{}) error {
	// Plan name
	if name, ok := doc["name"].(string); ok {
		fmt.Printf("Plan: %s\n", sanitizeOutput(name))
	}

	// Plan ID
	if planID, ok := doc["planId"].(string); ok {
		fmt.Printf("ID: %s\n", sanitizeOutput(planID))
	}

	// Type
	if planType, ok := doc["type"].(string); ok {
		fmt.Printf("Type: %s\n", sanitizeOutput(planType))
	}

	// System reference
	if sysRef, ok := doc["systemRef"].(string); ok {
		fmt.Printf("System: %s\n", sanitizeOutput(sysRef))
	}

	// Assessments
	if assessments, ok := doc["assessments"].([]interface{}); ok && len(assessments) > 0 {
		fmt.Printf("\nAssessments (%d):\n", len(assessments))
		for i, aRaw := range assessments {
			assessment, ok := aRaw.(map[string]interface{})
			if !ok {
				continue
			}
			baselineRef, _ := assessment["baselineRef"].(string)
			fmt.Printf("  %d. Baseline: %s\n", i+1, sanitizeOutput(baselineRef))

			if runner, ok := assessment["runner"].(map[string]interface{}); ok {
				if name, ok := runner["name"].(string); ok {
					fmt.Printf("     Runner: %s\n", sanitizeOutput(name))
				}
			}
		}
	}

	// Schedule
	if schedule, ok := doc["schedule"].(map[string]interface{}); ok {
		if cron, ok := schedule["cron"].(string); ok {
			desc := describeCron(cron)
			if desc != "" {
				fmt.Printf("\nSchedule: %s  (%s)\n", sanitizeOutput(cron), desc)
			} else {
				fmt.Printf("\nSchedule: %s\n", sanitizeOutput(cron))
			}
		}
	}

	return nil
}

// describeCron returns a human-readable label for common cron patterns.
func describeCron(cron string) string {
	switch cron {
	case "0 0 * * *", "0 0 0 * * *":
		return "daily"
	case "0 0 * * 0":
		return "weekly"
	case "0 0 1 * *":
		return "monthly"
	case "0 0 1 */3 *":
		return "quarterly"
	case "0 0 1 1 *":
		return "annually"
	default:
		return ""
	}
}
