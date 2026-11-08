package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/atomicfile"
	"github.com/spf13/cobra"
)

// NewLabelCmd creates the label command with set, show, and remove subcommands.
func NewLabelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "label",
		Short: "Manage labels and external IDs on components or documents",
		Long: `Add, remove, or display grouping labels and external identifiers.

The default --scope component manages components in results and system files.
Use --scope document for root metadata on amendments, baseline, evidence-package,
plan, and system files. Scopes are independent: metadata is never inherited or
copied to components, baselines, or referenced documents.

Labels are key=value grouping metadata, such as pipeline=nightly. External IDs
are scheme=value identifiers from another system: a component's CMDB asset ID,
or a document's producing CI run. They do not replace HDF identity fields and
are never component label selectors.

Examples:
  hdf label show results.json
  hdf label set package.json --scope document pipeline=nightly --external-id ci-run=project/run-4821
  hdf label set results.json system=Portal environment=production
  hdf label remove results.json system environment
  hdf label set results.json env=prod -o labeled.json
  hdf label set results.json --external-id cmdb=CI0012345`,
	}

	cmd.PersistentFlags().String("scope", "component", "Metadata owner: component (results/system) or document (amendments/baseline/evidence-package/plan/system)")

	cmd.AddCommand(newLabelShowCmd())
	cmd.AddCommand(newLabelSetCmd())
	cmd.AddCommand(newLabelRemoveCmd())

	return cmd
}

func newLabelShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <file>",
		Short: "Display labels and external IDs in the selected scope",
		Long: `Display metadata on components (default) or the document root (--scope document).
With --json, component scope returns an array of component summaries; document
scope returns an object with labels and externalIds maps.

Examples:
  hdf label show results.json
  hdf label show results.json --json
  hdf label show package.json --scope document --json`,
		Args: cobra.ExactArgs(1),
		RunE: runLabelShow,
	}
}

func newLabelSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <file> [<key>=<value>...]",
		Short: "Set labels and external IDs in the selected scope",
		Long: `Set labels on components (default) or the document root (--scope document).
Document scope also writes --external-id to the root externalIds map and rejects
--component-name, --component-id, and --generate-component-id.

Labels are specified as key=value pairs. Existing labels with the same key
are overwritten. The file is modified in-place unless --output is specified.

In component scope, --external-id scheme=value writes each target's externalIds.
Repeat the flag for several schemes. A scheme already present is overwritten;
other schemes are left as they are. The value is carried verbatim, so it may be
any non-empty string. By default every target gets the identifier; pass
--component-name to write it on one target only. The command fails, and writes
nothing, when the document has no target to carry the identifier, or when
--component-name matches no target or more than one.

--component-id and --generate-component-id stamp every target, and fail the same
way on a document with no target to stamp.

Examples:
  hdf label set package.json --scope document pipeline=nightly --external-id ci-run=project/run-4821
  hdf label set results.json system=Portal
  hdf label set results.json env=prod team=security
  hdf label set results.json env=prod -o labeled.json
  hdf label set results.json --component-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  hdf label set results.json --generate-component-id
  hdf label set results.json --external-id cmdb=CI0012345 --external-id emass=1234
  hdf label set results.json --external-id cmdb=CI0012345 --component-name web-server-01`,
		Args: cobra.MinimumNArgs(1),
		RunE: runLabelSet,
	}

	cmd.Flags().StringP("output", "o", "", "Write to a different file instead of modifying in-place")
	cmd.Flags().String("component-id", "", "Set componentId (a UUID) on all components")
	cmd.Flags().Bool("generate-component-id", false, "Generate a unique componentId for each component")
	cmd.Flags().StringArray("external-id", nil, "Set an external ID as scheme=value (repeatable, e.g. --external-id cmdb=CI0012345); surrounding whitespace is trimmed from the scheme, the value is carried verbatim")
	cmd.Flags().String("component-name", "", "Apply --external-id only to the component with this name")

	return cmd
}

func newLabelRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <file> [<key>...]",
		Short: "Remove labels and external IDs in the selected scope",
		Long: `Remove metadata from components (default) or the document root (--scope document).
Document scope removes --external-id schemes from the root and rejects
--component-name.

Missing keys are silently ignored. The file is modified in-place unless
--output is specified.

In component scope, --external-id scheme removes each target's external ID.
Repeat the flag for several schemes; pass --component-name to remove it from
one target only. The name must match exactly one component: a name is not
identity, so a document may carry two components with the same one, and an
ambiguous name is rejected before anything is written.

Examples:
  hdf label remove package.json --scope document pipeline --external-id ci-run
  hdf label remove results.json system
  hdf label remove results.json system environment
  hdf label remove results.json system -o cleaned.json
  hdf label remove results.json --external-id cmdb`,
		Args: cobra.MinimumNArgs(1),
		RunE: runLabelRemove,
	}

	cmd.Flags().StringP("output", "o", "", "Write to a different file instead of modifying in-place")
	cmd.Flags().StringArray("external-id", nil, "Remove an external ID scheme (repeatable, e.g. --external-id cmdb); surrounding whitespace is trimmed from the scheme")
	cmd.Flags().String("component-name", "", "Remove --external-id only from the component with this name")

	return cmd
}

// labelScope validates scope and incompatible flags before any file IO.
func labelScope(cmd *cobra.Command) (hdfdoc.MetadataScope, error) {
	value, _ := cmd.Flags().GetString("scope")
	scope := hdfdoc.MetadataScope(value)
	if scope != hdfdoc.ComponentScope && scope != hdfdoc.DocumentScope {
		return "", fmt.Errorf("invalid --scope %q: use component or document", value)
	}
	if scope == hdfdoc.DocumentScope {
		for _, flag := range []string{"component-id", "generate-component-id", "component-name"} {
			if cmd.Flags().Changed(flag) {
				return "", fmt.Errorf("--%s is incompatible with --scope document", flag)
			}
		}
	}
	return scope, nil
}

// gateLabelInput rejects unsupported types and invalid documents before render
// or mutation. Document metadata is supported only where the schema declares it.
func gateLabelInput(data []byte, scope hdfdoc.MetadataScope) error {
	documentTypes := []string{"amendments", "baseline", "evidence-package", "plan", "system"}
	allowed := []string{"results", "system"}
	command := "hdf label"
	if scope == hdfdoc.DocumentScope {
		allowed = documentTypes
		command += " (document scope)"
	}
	if actual, typeErr := requireDocumentType(data, allowed, command); typeErr != nil {
		if scope == hdfdoc.ComponentScope {
			for _, kind := range documentTypes {
				if actual == kind {
					return fmt.Errorf("hdf label component scope does not support %s; use --scope document", articleFor(actual))
				}
			}
		}
		return typeErr
	}
	if valErr := validateHDFDocument(data); valErr != nil {
		return fmt.Errorf("input failed schema validation: %w", valErr)
	}
	return nil
}

func runLabelShow(cmd *cobra.Command, args []string) error {
	scope, err := labelScope(cmd)
	if err != nil {
		return err
	}
	filePath := args[0]

	data, err := readInputFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if gateErr := gateLabelInput(data, scope); gateErr != nil {
		return gateErr
	}

	if scope == hdfdoc.DocumentScope {
		return showDocumentLabels(data)
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
		}
		printSortedPairs("  ", info.Labels)
		if len(info.ExternalIDs) > 0 {
			fmt.Println("  External IDs:")
			printSortedPairs("    ", info.ExternalIDs)
		}
	}

	return nil
}

func showDocumentLabels(data []byte) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	info := struct {
		Labels      map[string]string `json:"labels"`
		ExternalIDs map[string]string `json:"externalIds"`
	}{stringMapField(doc, "labels"), stringMapField(doc, "externalIds")}
	if jsonOutput {
		output, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize labels: %w", err)
		}
		fmt.Println(string(output))
		return nil
	}
	fmt.Println("Document labels:")
	if len(info.Labels) == 0 {
		fmt.Println("  (no labels)")
	}
	printSortedPairs("  ", info.Labels)
	fmt.Println("External IDs:")
	if len(info.ExternalIDs) == 0 {
		fmt.Println("  (no external IDs)")
	}
	printSortedPairs("  ", info.ExternalIDs)
	return nil
}

// printSortedPairs prints "key = value" lines in key order.
func printSortedPairs(indent string, pairs map[string]string) {
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s%s = %s\n", indent, k, pairs[k])
	}
}

// externalIDFlag reads the repeatable --external-id flag. pflag reports a lone
// empty value as no values at all, which would turn `--external-id ""` into a
// silent no-op, so a flag that was set but came back empty is restored.
func externalIDFlag(cmd *cobra.Command) []string {
	values, _ := cmd.Flags().GetStringArray("external-id")
	if len(values) == 0 && cmd.Flags().Changed("external-id") {
		return []string{""}
	}
	return values
}

// labelSetRequest is everything `label set` was asked to write, parsed and
// validated before the file is read so a bad argument can never leave a partial
// write behind.
type labelSetRequest struct {
	labels        map[string]string
	componentID   string
	generateCID   bool
	externalIDs   map[string]string
	componentName string
}

func parseLabelSetRequest(cmd *cobra.Command, labelPairs []string) (labelSetRequest, error) {
	var req labelSetRequest
	req.componentID, _ = cmd.Flags().GetString("component-id")
	req.generateCID, _ = cmd.Flags().GetBool("generate-component-id")
	req.componentName, _ = cmd.Flags().GetString("component-name")
	externalIDPairs := externalIDFlag(cmd)

	if len(labelPairs) == 0 && req.componentID == "" && !req.generateCID && len(externalIDPairs) == 0 && req.componentName == "" {
		return req, fmt.Errorf("no labels, component-id or external-id flags provided; nothing to set\n" +
			"Usage: hdf label set <file> key=value [key=value...]\n" +
			"  or:  hdf label set <file> --component-id <uuid>\n" +
			"  or:  hdf label set <file> --generate-component-id\n" +
			"  or:  hdf label set <file> --external-id <scheme>=<value>")
	}

	var err error
	if req.labels, err = parseLabelsFlag(labelPairs); err != nil {
		return req, err
	}
	if idErr := checkComponentIDFlag(req.componentID); idErr != nil {
		return req, idErr
	}
	if req.externalIDs, err = parseExternalIDsFlag(externalIDPairs); err != nil {
		return req, err
	}
	if req.componentName != "" {
		if len(req.externalIDs) == 0 {
			return req, fmt.Errorf("--component-name selects the component for --external-id; pass at least one --external-id")
		}
		if len(req.labels) > 0 || req.componentID != "" || req.generateCID {
			return req, fmt.Errorf("--component-name applies to --external-id only; labels and component-id flags are written to every component, so set them in a separate invocation")
		}
	}
	return req, nil
}

func runLabelSet(cmd *cobra.Command, args []string) error {
	scope, err := labelScope(cmd)
	if err != nil {
		return err
	}
	filePath := args[0]

	req, err := parseLabelSetRequest(cmd, args[1:])
	if err != nil {
		return err
	}

	data, err := readInputFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if gateErr := gateLabelInput(data, scope); gateErr != nil {
		return gateErr
	}

	result, err := hdfdoc.UpdateMetadata(data, scope, req.componentName, hdfdoc.MetadataChanges{Labels: req.labels, ExternalIDs: req.externalIDs})
	if err != nil {
		return err
	}

	if req.componentID != "" || req.generateCID {
		result, err = hdfdoc.ApplyComponentID(result, req.componentID, req.generateCID)
		if err != nil {
			return err
		}
	}

	outputPath, _ := cmd.Flags().GetString("output")
	return writeLabelOutput(result, filePath, outputPath)
}

// checkComponentIDFlag accepts an unset --component-id; a set one must be a UUID.
func checkComponentIDFlag(componentID string) error {
	if componentID == "" {
		return nil
	}
	if err := hdfdoc.ValidateComponentID(componentID); err != nil {
		return fmt.Errorf("invalid --component-id: %w", err)
	}
	return nil
}

func runLabelRemove(cmd *cobra.Command, args []string) error {
	scope, err := labelScope(cmd)
	if err != nil {
		return err
	}
	filePath := args[0]
	keys := args[1:]

	componentName, _ := cmd.Flags().GetString("component-name")
	schemes, err := parseExternalIDSchemes(externalIDFlag(cmd))
	if err != nil {
		return err
	}

	if len(keys) == 0 && len(schemes) == 0 && componentName == "" {
		return fmt.Errorf("no label keys or --external-id schemes provided; nothing to remove\n" +
			"Usage: hdf label remove <file> key [key...]\n" +
			"  or:  hdf label remove <file> --external-id <scheme>")
	}
	if componentName != "" {
		if len(schemes) == 0 {
			return fmt.Errorf("--component-name selects the component for --external-id; pass at least one --external-id")
		}
		if len(keys) > 0 {
			return fmt.Errorf("--component-name applies to --external-id only; label keys are removed from every component, so remove them in a separate invocation")
		}
	}

	data, err := readInputFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if gateErr := gateLabelInput(data, scope); gateErr != nil {
		return gateErr
	}

	result, err := hdfdoc.UpdateMetadata(data, scope, componentName, hdfdoc.MetadataChanges{RemoveLabels: keys, RemoveExternalIDs: schemes})
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

	if err := validateHDFDocument(data); err != nil {
		return fmt.Errorf("document failed validation before write: %w", err)
	}

	// Ensure trailing newline for well-formed JSON files
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	if err := atomicfile.WriteFile(target, data, 0o600); err != nil {
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
