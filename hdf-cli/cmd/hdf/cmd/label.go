package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"

	"github.com/spf13/cobra"
)

// NewLabelCmd creates the label command with set, show, and remove subcommands.
func NewLabelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "label",
		Short: "Manage labels on HDF file targets",
		Long: `Add, remove, or display labels on targets in an HDF file.

Labels are key=value pairs stored on each target in the HDF document.

Examples:
  hdf label show results.json
  hdf label set results.json system=Portal environment=production
  hdf label remove results.json system environment
  hdf label set results.json env=prod -o labeled.json`,
	}

	cmd.AddCommand(newLabelShowCmd())
	cmd.AddCommand(newLabelSetCmd())
	cmd.AddCommand(newLabelRemoveCmd())

	return cmd
}

func newLabelShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <file>",
		Short: "Display labels on all targets",
		Long: `Display the labels currently set on all targets in an HDF file.

Examples:
  hdf label show results.json
  hdf label show results.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: runLabelShow,
	}
}

func newLabelSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <file> <key>=<value> [<key>=<value>...]",
		Short: "Set labels on all targets",
		Long: `Set one or more labels on all targets in an HDF file.

Labels are specified as key=value pairs. Existing labels with the same key
are overwritten. The file is modified in-place unless --output is specified.

Examples:
  hdf label set results.json system=Portal
  hdf label set results.json env=prod team=security
  hdf label set results.json env=prod -o labeled.json
  hdf label set results.json --component-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  hdf label set results.json --generate-component-id`,
		Args: cobra.MinimumNArgs(1),
		RunE: runLabelSet,
	}

	cmd.Flags().StringP("output", "o", "", "Write to a different file instead of modifying in-place")
	cmd.Flags().String("component-id", "", "Set componentId on all components")
	cmd.Flags().Bool("generate-component-id", false, "Generate a unique componentId for each component")

	return cmd
}

func newLabelRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <file> <key> [<key>...]",
		Short: "Remove labels from all targets",
		Long: `Remove one or more label keys from all targets in an HDF file.

Missing keys are silently ignored. The file is modified in-place unless
--output is specified.

Examples:
  hdf label remove results.json system
  hdf label remove results.json system environment
  hdf label remove results.json system -o cleaned.json`,
		Args: cobra.MinimumNArgs(2),
		RunE: runLabelRemove,
	}

	cmd.Flags().StringP("output", "o", "", "Write to a different file instead of modifying in-place")

	return cmd
}

func runLabelShow(_ *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if _, typeErr := requireDocumentType(data, []string{"results"}, "hdf label"); typeErr != nil {
		return typeErr
	}

	infos, err := extractComponentLabels(data)
	if err != nil {
		return err
	}

	if jsonOutput {
		output, err := json.MarshalIndent(infos, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize labels: %w", err)
		}
		fmt.Println(string(output))
		return nil
	}

	if len(infos) == 0 {
		fmt.Println("No components found.")
		return nil
	}

	for i, info := range infos {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("Component: %s [%s]\n", info.Name, info.Type)
		if len(info.Labels) == 0 {
			fmt.Println("  (no labels)")
		} else {
			keys := make([]string, 0, len(info.Labels))
			for k := range info.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("  %s = %s\n", k, info.Labels[k])
			}
		}
	}

	return nil
}

func runLabelSet(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	labelPairs := args[1:]

	componentID, _ := cmd.Flags().GetString("component-id")
	generateCID, _ := cmd.Flags().GetBool("generate-component-id")

	if len(labelPairs) == 0 && componentID == "" && !generateCID {
		return fmt.Errorf("no labels or component-id flags provided; nothing to set\n" +
			"Usage: hdf label set <file> key=value [key=value...]\n" +
			"  or:  hdf label set <file> --component-id <uuid>\n" +
			"  or:  hdf label set <file> --generate-component-id")
	}

	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	result := data

	// Apply key=value labels if provided
	if len(labelPairs) > 0 {
		labels, parseErr := parseLabelsFlag(labelPairs)
		if parseErr != nil {
			return parseErr
		}
		result, err = hdfdoc.ApplyLabels(result, labels)
		if err != nil {
			return err
		}
	}

	// Apply --component-id or --generate-component-id
	if componentID != "" || generateCID {
		result, err = hdfdoc.ApplyComponentID(result, componentID, generateCID)
		if err != nil {
			return err
		}
	}

	outputPath, _ := cmd.Flags().GetString("output")
	return writeLabelOutput(result, filePath, outputPath)
}

// applyComponentIDs stamps componentId on all components in the JSON document.
// If fixedID is non-empty, all components get that ID. If generate is true,
// each component gets a unique UUID.

func runLabelRemove(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	keys := args[1:]

	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	result, err := removeLabels(data, keys)
	if err != nil {
		return err
	}

	outputPath, _ := cmd.Flags().GetString("output")
	return writeLabelOutput(result, filePath, outputPath)
}

// writeLabelOutput writes the result to the output path, or the original file
// if no output path is specified.
func writeLabelOutput(data []byte, originalPath, outputPath string) error {
	target := originalPath
	if outputPath != "" {
		target = outputPath
	}

	// Ensure trailing newline for well-formed JSON files
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	if err := os.WriteFile(target, data, 0o600); err != nil { // #nosec G703 -- output path from user CLI arg
		return fmt.Errorf("failed to write file: %w", err)
	}

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "Labels written to %s\n", target)
	} else {
		fmt.Fprintf(os.Stderr, "Labels updated in %s\n", target)
	}

	return nil
}

// formatLabelPairs formats a label map as a sorted, comma-separated string
// of key=value pairs for display purposes.
func formatLabelPairs(labels map[string]string) string {
	if len(labels) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, labels[k]))
	}
	return strings.Join(pairs, ", ")
}
