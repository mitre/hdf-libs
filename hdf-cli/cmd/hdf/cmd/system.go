package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// NewSystemCmd creates the system command group with info subcommand.
func NewSystemCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Work with HDF system documents",
		Long: `Commands for viewing and managing HDF system documents.

An HDF system document describes a system's authorization boundary, components,
baselines, and interconnections.

Examples:
  hdf system info portal-prod.hdf-system.json
  hdf system info portal-prod.hdf-system.json --json`,
	}

	cmd.AddCommand(newSystemInfoCmd())

	return cmd
}

func newSystemInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <file>",
		Short: "Display summary information about an HDF system document",
		Long: `Display summary information about an HDF system document including:
- System name, authorization status, and categorization level
- Description
- Components with their baselines and target selectors
- Interconnections

Examples:
  hdf system info portal-prod.hdf-system.json
  hdf system info portal-prod.hdf-system.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDocInfo(args[0], outputSystemInfoHuman)
		},
	}
}

func outputSystemInfoHuman(doc map[string]interface{}) error {
	// System name
	if name, ok := doc["name"].(string); ok {
		fmt.Printf("System: %s\n", sanitizeOutput(name))
	}

	// Authorization status
	if status, ok := doc["authorizationStatus"].(string); ok {
		fmt.Printf("Authorization: %s\n", sanitizeOutput(status))
	}

	// Categorization level
	if level, ok := doc["categorizationLevel"].(string); ok {
		fmt.Printf("Categorization: %s\n", sanitizeOutput(level))
	}

	// Description
	if desc, ok := doc["description"].(string); ok {
		fmt.Printf("Description: %s\n", sanitizeOutput(desc))
	}

	// Components
	if components, ok := doc["components"].([]interface{}); ok && len(components) > 0 {
		fmt.Printf("\nComponents (%d):\n", len(components))
		for _, cRaw := range components {
			comp, ok := cRaw.(map[string]interface{})
			if !ok {
				continue
			}
			printSystemComponent(comp)
		}
	}

	// Interconnections
	printInterconnections(doc)

	return nil
}

// printSystemComponent prints a single system component's details.
func printSystemComponent(comp map[string]interface{}) {
	name, _ := comp["name"].(string)
	compType, _ := comp["type"].(string)
	fmt.Printf("  %s (%s)\n", sanitizeOutput(name), sanitizeOutput(compType))

	// Baselines
	if refs, ok := comp["baselineRefs"].([]interface{}); ok && len(refs) > 0 {
		names := make([]string, 0, len(refs))
		for _, r := range refs {
			if s, ok := r.(string); ok {
				names = append(names, sanitizeOutput(s))
			}
		}
		fmt.Printf("    Baselines: %s\n", strings.Join(names, ", "))
	}

	// Target selector
	if sel, ok := comp["targetSelector"].(map[string]interface{}); ok && len(sel) > 0 {
		pairs := make([]string, 0, len(sel))
		keys := make([]string, 0, len(sel))
		for k := range sel {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if v, ok := sel[k].(string); ok {
				pairs = append(pairs, fmt.Sprintf("%s: %s", k, v))
			}
		}
		fmt.Printf("    Target selector: {%s}\n", strings.Join(pairs, ", "))
	}

	// Description
	if desc, ok := comp["description"].(string); ok {
		fmt.Printf("    Description: %s\n", sanitizeOutput(desc))
	}
}

// printInterconnections prints the interconnections section.
func printInterconnections(doc map[string]interface{}) {
	interconnections, ok := doc["interconnections"].([]interface{})
	if !ok || len(interconnections) == 0 {
		return
	}
	fmt.Printf("\nInterconnections (%d):\n", len(interconnections))
	for _, iRaw := range interconnections {
		ic, ok := iRaw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := ic["name"].(string)
		direction, _ := ic["direction"].(string)
		dirStr := ""
		if direction != "" {
			dirStr = fmt.Sprintf(" (%s)", sanitizeOutput(direction))
		}
		fmt.Printf("  %s%s\n", sanitizeOutput(name), dirStr)
	}
}
