package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/spf13/cobra"
)

func newPlanCreateCmd() *cobra.Command {
	var (
		outputPath string
		planName   string
		baseline   string
		planID     string
	)

	cmd := &cobra.Command{
		Use:   "create [system-file]",
		Short: "Create an assessment plan",
		Long: `Create an HDF assessment plan, either from a system document or standalone.

From system file (positional arg):
  Reads the system document and creates an assessment entry for each
  component's baseline refs. The system file path is recorded as systemRef.

Standalone (--name + --baseline):
  Creates a minimal plan with a single assessment referencing the given
  baseline. Use 'hdf plan set' to add system-ref and other fields later.

Examples:
  hdf plan create portal-prod.hdf-system.json
  hdf plan create portal-prod.hdf-system.json -o plan.json
  hdf plan create --name "RHEL9 Assessment" --baseline RHEL9-STIG -o plan.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				return runPlanCreateFromSystem(args[0], planID, outputPath)
			}
			if planName == "" || baseline == "" {
				return fmt.Errorf("either provide a system file, or use --name and --baseline to create a standalone plan")
			}
			return runPlanCreateStandalone(planName, baseline, planID, outputPath)
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&planName, "name", "", "Plan name (required for standalone creation)")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Baseline reference for standalone plan (e.g. 'RHEL9-STIG')")
	cmd.Flags().StringVar(&planID, "plan-id", "", "Plan UUID (auto-generated if omitted)")

	return cmd
}

func runPlanCreateStandalone(planName, baseline, planID, outputPath string) error {
	if planID == "" {
		planID = uuid.New().String()
	}

	plan := map[string]interface{}{
		"planId": planID,
		"name":   planName,
		"assessments": []map[string]interface{}{
			{"baselineRef": baseline},
		},
		"generator": map[string]interface{}{
			"name":    "hdf-cli",
			"version": version,
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}

	return writePlanOutput(plan, outputPath)
}

func runPlanCreateFromSystem(systemFile, planID, outputPath string) error {
	data, err := os.ReadFile(systemFile) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read system file: %w", err)
	}

	var sysDoc map[string]interface{}
	if err := json.Unmarshal(data, &sysDoc); err != nil {
		return fmt.Errorf("failed to parse system document: %w", err)
	}

	sysName, _ := sysDoc["name"].(string)
	if sysName == "" {
		return fmt.Errorf("system document missing required 'name' field")
	}

	components, _ := sysDoc["components"].([]interface{})

	// Build assessments from components
	assessments := make([]map[string]interface{}, 0)
	for _, cRaw := range components {
		comp, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}
		refs, ok := comp["baselineRefs"].([]interface{})
		if !ok || len(refs) == 0 {
			continue
		}
		for _, refRaw := range refs {
			ref, ok := refRaw.(string)
			if !ok {
				continue
			}
			assessment := map[string]interface{}{
				"baselineRef": ref,
			}
			if selector, ok := comp["targetSelector"].(map[string]interface{}); ok && len(selector) > 0 {
				assessment["targetSelector"] = selector
			}
			assessments = append(assessments, assessment)
		}
	}

	if len(assessments) == 0 {
		return fmt.Errorf("no assessments generated: system has no components with baselineRefs")
	}

	// Build plan
	if planID == "" {
		planID = uuid.New().String()
	}
	planName := hdfutil.ToKebabCase(sysName) + "-assessment-plan"
	plan := map[string]interface{}{
		"planId":      planID,
		"name":        planName,
		"systemRef":   systemFile,
		"assessments": assessments,
		"generator": map[string]interface{}{
			"name":    "hdf-cli",
			"version": version,
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}

	return writePlanOutput(plan, outputPath)
}

func writePlanOutput(plan map[string]interface{}, outputPath string) error {
	output, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize plan: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil {
		return fmt.Errorf("failed to write plan: %w", err)
	}

	assessments, _ := plan["assessments"].([]map[string]interface{})
	fmt.Fprintf(os.Stderr, "Plan written to %s (%d assessments)\n", outputPath, len(assessments))
	return nil
}
