package cmd

import (
	"encoding/json"
	"fmt"
	"os"
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
	cmd.AddCommand(newSystemCreateCmd())
	cmd.AddCommand(newSystemSetCmd())
	cmd.AddCommand(newSystemAddComponentCmd())
	cmd.AddCommand(newSystemUpdateComponentCmd())

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
			return runDocInfo(args[0], "hdf system info", []string{"system"}, outputSystemInfoHuman)
		},
	}
}

func outputSystemInfoHuman(doc map[string]interface{}) error {
	// System name
	if name, ok := doc["name"].(string); ok {
		fmt.Printf("System: %s\n", sanitizeOutput(name))
	}

	// System ID
	if id, ok := doc["systemId"].(string); ok {
		fmt.Printf("System ID: %s\n", sanitizeOutput(id))
	}

	// Authorization status
	if status, ok := doc["authorizationStatus"].(string); ok {
		fmt.Printf("Authorization: %s\n", sanitizeOutput(status))
	}

	// Categorization level
	if level, ok := doc["categorizationLevel"].(string); ok {
		fmt.Printf("Categorization: %s\n", sanitizeOutput(level))
	}

	// Owner
	if owner, ok := doc["owner"].(map[string]interface{}); ok {
		id, _ := owner["identifier"].(string)
		ownerType, _ := owner["type"].(string)
		if id != "" {
			fmt.Printf("Owner: %s (%s)\n", sanitizeOutput(id), sanitizeOutput(ownerType))
		}
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

	// Data flows
	printDataFlows(doc)

	return nil
}

func newSystemSetCmd() *cobra.Command {
	var (
		owner       string
		description string
		name        string
		systemID    string
		outputPath  string
		unsetFields []string
	)

	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Set, update, or unset top-level fields on an HDF system document",
		Long: `Set, update, or remove top-level metadata fields on an existing HDF system document.
Reads the file, applies the specified changes, and writes it back (or to -o).

Use --unset to remove optional fields. Required fields (name, components) cannot be unset.

Examples:
  hdf system set system.json --owner "team@agency.gov"
  hdf system set system.json --owner "Platform Team" --description "Production portal"
  hdf system set system.json --unset owner
  hdf system set system.json --unset description --owner "new@agency.gov"
  hdf system set system.json --name "New Name" --system-id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  hdf system set system.json --owner "team@agency.gov" -o updated.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if owner == "" && description == "" && name == "" && systemID == "" && len(unsetFields) == 0 {
				return fmt.Errorf("at least one field flag is required (--owner, --description, --name, --system-id, --unset)")
			}
			return runSystemSet(args[0], outputPath, owner, description, name, systemID, unsetFields)
		},
	}

	cmd.Flags().StringVar(&owner, "owner", "", "System owner (email or plain text name)")
	cmd.Flags().StringVar(&description, "description", "", "System description")
	cmd.Flags().StringVar(&name, "name", "", "System name")
	cmd.Flags().StringVar(&systemID, "system-id", "", "System UUID")
	cmd.Flags().StringArrayVar(&unsetFields, "unset", nil, "Remove a field (repeatable; e.g. --unset owner --unset description)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

// requiredSystemFields cannot be removed with --unset.
var requiredSystemFields = map[string]bool{
	"name":       true,
	"components": true,
}

func runSystemSet(inputPath, outputPath, owner, description, name, systemID string, unsetFields []string) error {
	data, err := os.ReadFile(inputPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read system document: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse system document: %w", err)
	}

	if name != "" {
		doc["name"] = name
	}
	if description != "" {
		doc["description"] = description
	}
	if systemID != "" {
		doc["systemId"] = systemID
	}
	if owner != "" {
		ownerType := identityType(owner)
		doc["owner"] = map[string]interface{}{
			"type":       ownerType,
			"identifier": owner,
		}
	}

	// Process --unset flags (after sets, so --unset wins if both specified for same field)
	for _, field := range unsetFields {
		if requiredSystemFields[field] {
			return fmt.Errorf("cannot unset required field %q", field)
		}
		delete(doc, field)
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize system document: %w", err)
	}

	target := inputPath
	if outputPath != "" {
		target = outputPath
	}

	if err := os.WriteFile(target, output, 0o600); err != nil { // #nosec G306 -- intentional 0600
		return fmt.Errorf("failed to write system document: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated %s\n", target)
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

	// Owner
	if owner, ok := comp["owner"].(map[string]interface{}); ok {
		id, _ := owner["identifier"].(string)
		if id != "" {
			fmt.Printf("    Owner: %s\n", sanitizeOutput(id))
		}
	}

	// Description
	if desc, ok := comp["description"].(string); ok {
		fmt.Printf("    Description: %s\n", sanitizeOutput(desc))
	}
}

// printDataFlows prints the data flows section.
func printDataFlows(doc map[string]interface{}) {
	flows, ok := doc["dataFlows"].([]interface{})
	if !ok || len(flows) == 0 {
		return
	}
	fmt.Printf("\nData Flows (%d):\n", len(flows))
	printDataFlowList(flows)
}

// printDataFlowList prints individual data flow entries. Shared by system info and list.
func printDataFlowList(flows []interface{}) {
	tbl := NewTable(
		Column{Header: "From"},
		Column{Header: "To"},
		Column{Header: "Protocol"},
		Column{Header: "Description"},
	)
	for _, fRaw := range flows {
		flow, ok := fRaw.(map[string]interface{})
		if !ok {
			continue
		}
		from, _ := flow["from"].(string)
		to, _ := flow["to"].(string)
		protocol, _ := flow["protocol"].(string)
		desc, _ := flow["description"].(string)
		tbl.AddRow(sanitizeOutput(from), sanitizeOutput(to), sanitizeOutput(protocol), sanitizeOutput(desc))
	}
	tbl.Render()
}
