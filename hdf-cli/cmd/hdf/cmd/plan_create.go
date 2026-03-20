package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newPlanCreateCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "create <system-file>",
		Short: "Generate an assessment plan from a system definition",
		Long: `Generate an HDF assessment plan from an hdf-system document.

For each component in the system, an assessment entry is created
referencing the component's baseline refs. The system file path
is recorded as the plan's systemRef.

Examples:
  hdf plan create portal-prod.hdf-system.json
  hdf plan create portal-prod.hdf-system.json -o plan.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runPlanCreate(args[0], outputPath)
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")

	return cmd
}

func runPlanCreate(systemFile, outputPath string) error {
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
	planName := toKebabCase(sysName) + "-assessment-plan"
	plan := map[string]interface{}{
		"name":        planName,
		"type":        "automated",
		"systemRef":   systemFile,
		"assessments": assessments,
		"generator": map[string]interface{}{
			"name":    "hdf-cli",
			"version": version,
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}

	output, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize plan: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil { // #nosec G304 -- CLI writes to user-specified path
		return fmt.Errorf("failed to write plan: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Plan written to %s (%d assessments)\n", outputPath, len(assessments))
	return nil
}

// toKebabCase converts a title to a kebab-case slug.
func toKebabCase(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
