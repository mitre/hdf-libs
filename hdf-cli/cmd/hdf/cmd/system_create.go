package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func newSystemCreateCmd() *cobra.Command {
	var (
		fromFile            string
		outputPath          string
		systemName          string
		componentName       string
		ownerEmail          string
		systemID            string
		description         string
		embed               bool
		generateComponentID bool
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Bootstrap an HDF system document from a results file or SBOM",
		Long: `Generate an HDF system document by extracting targets and baselines
from an HDF results file, or by importing component metadata from a
CycloneDX/SPDX SBOM.

Examples:
  hdf system create --from results.json
  hdf system create --from results.json -o system.json
  hdf system create --from results.json --name "Portal Prod" -o system.json
  hdf system create --from sbom.cdx.json --component-name "WebTier" -o system.json
  hdf system create --from results.json --owner team@agency.gov --description "Prod portal"`,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts := systemCreateOpts{
				fromFile:            fromFile,
				systemName:          systemName,
				componentName:       componentName,
				outputPath:          outputPath,
				ownerEmail:          ownerEmail,
				systemID:            systemID,
				description:         description,
				embed:               embed,
				generateComponentID: generateComponentID,
			}
			return runSystemCreate(opts)
		},
	}

	cmd.Flags().StringVar(&fromFile, "from", "", "HDF results file or CycloneDX/SPDX SBOM (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&systemName, "name", "", "System name (default: derived from input)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name (for SBOM input)")
	cmd.Flags().StringVar(&ownerEmail, "owner", "", "System owner (email or plain text name)")
	cmd.Flags().StringVar(&systemID, "system-id", "", "System UUID (auto-generated if omitted)")
	cmd.Flags().StringVar(&description, "description", "", "System description")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")
	cmd.Flags().BoolVar(&generateComponentID, "generate-component-id", false, "Auto-assign UUID componentId to each component")

	if err := cmd.MarkFlagRequired("from"); err != nil {
		panic(fmt.Sprintf("failed to mark flag required: %v", err))
	}

	return cmd
}

// targetTypeToComponentType maps HDF Target.type to HDF Component.type. As of
// v3.3.0, Component.type is a closed 11-value enum and shares the same values
// with Target.type, so the mapping is identity for known values. Unknown
// values fall back to "application" (the most generic valid type).
func targetTypeToComponentType(targetType string) string {
	switch targetType {
	case "host", "containerImage", "containerInstance", "containerPlatform",
		"cloudAccount", "cloudResource", "application", "database",
		"network", "repository", "artifact":
		return targetType
	default:
		return compTypeApplication
	}
}

// isURL returns true if the string looks like an HTTP(S) URL.
func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

type systemCreateOpts struct {
	fromFile            string
	systemName          string
	componentName       string
	outputPath          string
	ownerEmail          string
	systemID            string
	description         string
	embed               bool
	generateComponentID bool
}

func runSystemCreate(opts systemCreateOpts) error {
	// If --from is a URL, we can't read the file — require metadata flags
	if isURL(opts.fromFile) {
		return runSystemCreateFromSBOMRef(opts.fromFile, opts.systemName, opts.componentName, opts.outputPath)
	}

	data, err := os.ReadFile(opts.fromFile) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse input file: %w", err)
	}

	// Detect input type: HDF Results vs CycloneDX SBOM
	if bomFormat, ok := doc["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		return runSystemCreateFromSBOM(doc, opts.fromFile, opts.systemName, opts.componentName, opts.outputPath, sbomFormatCycloneDX, opts)
	}

	// Check for SPDX (has spdxVersion field)
	if _, ok := doc["spdxVersion"]; ok {
		return runSystemCreateFromSBOM(doc, opts.fromFile, opts.systemName, opts.componentName, opts.outputPath, sbomFormatSPDX, opts)
	}

	// Default: treat as HDF Results
	return runSystemCreateFromResults(doc, opts.systemName, opts.outputPath, opts)
}

// runSystemCreateFromSBOMRef creates a system document from a remote SBOM URI.
// Since we can't read the file, --component-name is required.
func runSystemCreateFromSBOMRef(sbomURI, systemName, componentName, outputPath string) error {
	if componentName == "" {
		return fmt.Errorf("--component-name is required when --from is a URL\n" +
			"(cannot read remote file to extract component metadata)")
	}

	if systemName == "" {
		systemName = componentName + "-system"
	}

	// Guess format from URL extension
	sbomFormat := guessFormatFromURI(sbomURI)

	comp := map[string]interface{}{
		"name":    componentName,
		"type":    compTypeApplication,
		"sbomRef": sbomURI,
	}
	if sbomFormat != "" {
		comp["sbomFormat"] = sbomFormat
	}

	fmt.Fprintf(os.Stderr, "Created component %q from URI (type: %s)\n", componentName, compTypeApplication)
	fmt.Fprintf(os.Stderr, "Note: component type defaulted to %q; edit the system document to correct if needed\n", compTypeApplication)
	return writeSystemDoc(systemName, []map[string]interface{}{comp}, outputPath, systemCreateOpts{})
}

// guessFormatFromURI attempts to determine SBOM format from the URI extension.
func guessFormatFromURI(uri string) string {
	lower := strings.ToLower(uri)
	if strings.Contains(lower, ".cdx.") || strings.Contains(lower, "cyclonedx") {
		return sbomFormatCycloneDX
	}
	if strings.Contains(lower, ".spdx.") || strings.Contains(lower, "spdx") {
		return sbomFormatSPDX
	}
	return ""
}

func runSystemCreateFromResults(results map[string]interface{}, systemName, outputPath string, opts systemCreateOpts) error {
	// Extract targets
	targetsRaw, ok := results["components"].([]interface{})
	if !ok || len(targetsRaw) == 0 {
		return fmt.Errorf("results file has no targets: cannot bootstrap system document")
	}

	// Derive system name from first target if not provided
	if systemName == "" {
		if first, ok := targetsRaw[0].(map[string]interface{}); ok {
			if name, ok := first["name"].(string); ok {
				systemName = name
			}
		}
		if systemName == "" {
			systemName = "system"
		}
	}

	// Collect baseline names
	baselineNames := extractBaselineNames(results)

	// Build components from targets
	components := make([]map[string]interface{}, 0, len(targetsRaw))
	for _, tRaw := range targetsRaw {
		target, ok := tRaw.(map[string]interface{})
		if !ok {
			continue
		}
		comp := buildComponentFromTarget(target, baselineNames)
		components = append(components, comp)
	}

	return writeSystemDoc(systemName, components, outputPath, opts)
}

func runSystemCreateFromSBOM(doc map[string]interface{}, filePath, systemName, componentName, outputPath, sbomFormat string, opts systemCreateOpts) error {
	// Extract component metadata from SBOM
	if componentName == "" {
		componentName = extractSBOMComponentName(doc, sbomFormat)
	}
	if componentName == "" {
		return fmt.Errorf("cannot determine component name from SBOM; use --component-name to specify")
	}

	if systemName == "" {
		systemName = componentName + "-system"
	}

	// Detect component type from SBOM metadata
	compType := extractSBOMComponentType(doc, sbomFormat)

	comp := map[string]interface{}{
		"name":       componentName,
		"type":       compType,
		"sbomRef":    filepath.ToSlash(filePath), // schema requires uri-reference; Windows backslashes are invalid
		"sbomFormat": sbomFormat,
	}

	// Embed full SBOM data if --embed is set
	if opts.embed {
		comp["sbom"] = doc
	}

	// Extract version if available
	if ver := extractSBOMComponentVersion(doc, sbomFormat); ver != "" {
		comp["description"] = fmt.Sprintf("%s v%s", componentName, ver)
	}

	fmt.Fprintf(os.Stderr, "Imported %s SBOM as component %q (type: %s)\n", sbomFormat, componentName, compType)
	return writeSystemDoc(systemName, []map[string]interface{}{comp}, outputPath, opts)
}

// extractSBOMComponentName gets the top-level component name from a CycloneDX or SPDX SBOM.
func extractSBOMComponentName(doc map[string]interface{}, format string) string {
	switch format {
	case sbomFormatCycloneDX:
		if meta, ok := doc["metadata"].(map[string]interface{}); ok {
			if comp, ok := meta["component"].(map[string]interface{}); ok {
				if name, ok := comp["name"].(string); ok {
					return name
				}
			}
		}
	case sbomFormatSPDX:
		if name, ok := doc["name"].(string); ok {
			return name
		}
	}
	return ""
}

// extractSBOMComponentType maps SBOM component type to HDF Component.type
// (the closed 11-value enum). CycloneDX uses a different vocabulary than
// HDF, so we map across.
func extractSBOMComponentType(doc map[string]interface{}, format string) string {
	if format == sbomFormatCycloneDX {
		if meta, ok := doc["metadata"].(map[string]interface{}); ok {
			if comp, ok := meta["component"].(map[string]interface{}); ok {
				switch comp["type"] {
				case "application", "library", "framework":
					return compTypeApplication
				case "container":
					return "containerImage"
				case "firmware", "device", "operating-system", "platform":
					return "host"
				}
			}
		}
	}
	return compTypeApplication
}

// extractSBOMComponentVersion gets the version from SBOM metadata.
func extractSBOMComponentVersion(doc map[string]interface{}, format string) string {
	if format == sbomFormatCycloneDX {
		if meta, ok := doc["metadata"].(map[string]interface{}); ok {
			if comp, ok := meta["component"].(map[string]interface{}); ok {
				if ver, ok := comp["version"].(string); ok {
					return ver
				}
			}
		}
	}
	return ""
}

func writeSystemDoc(systemName string, components []map[string]interface{}, outputPath string, opts systemCreateOpts) error {
	// Auto-generate systemId if not provided
	systemID := opts.systemID
	if systemID == "" {
		systemID = uuid.New().String()
	}

	// Stamp componentId on components that lack one
	if opts.generateComponentID {
		for _, comp := range components {
			if _, hasID := comp["componentId"]; !hasID {
				comp["componentId"] = uuid.New().String()
			}
		}
	}

	sysDoc := map[string]interface{}{
		"systemId":   systemID,
		"name":       systemName,
		"components": components,
		"dataFlows":  []interface{}{},
		"generator": map[string]interface{}{
			"name":    "hdf-cli",
			"version": version,
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}

	if opts.description != "" {
		sysDoc["description"] = opts.description
	}

	if opts.ownerEmail != "" {
		ownerType := identityType(opts.ownerEmail)
		sysDoc["owner"] = map[string]interface{}{
			"type":       ownerType,
			"identifier": opts.ownerEmail,
		}
	}

	output, err := json.MarshalIndent(sysDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize system document: %w", err)
	}

	if err := validateHDFOutput(output); err != nil {
		return fmt.Errorf("system document failed validation before write: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil {
		return fmt.Errorf("failed to write system document: %w", err)
	}
	fmt.Fprintf(os.Stderr, "System document written to %s (%d components)\n", outputPath, len(components))
	return nil
}

// extractBaselineNames returns the list of baseline names from the results document.
func extractBaselineNames(results map[string]interface{}) []string {
	baselines, ok := results["baselines"].([]interface{})
	if !ok {
		return nil
	}

	names := make([]string, 0, len(baselines))
	for _, bRaw := range baselines {
		bl, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := bl["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// buildComponentFromTarget creates a system component from a results component.
func buildComponentFromTarget(target map[string]interface{}, baselineNames []string) map[string]interface{} {
	name, _ := target["name"].(string)
	targetType, _ := target["type"].(string)

	comp := map[string]interface{}{
		"name": name,
		"type": targetTypeToComponentType(targetType),
	}

	// Wire all baselines as refs
	if len(baselineNames) > 0 {
		comp["baselineRefs"] = baselineNames
	}

	// Carry forward componentId if present
	if id, ok := target["componentId"].(string); ok && id != "" {
		comp["componentId"] = id
	}

	// Carry forward version
	if v, ok := target["version"].(string); ok && v != "" {
		comp["version"] = v
	}

	// Carry forward description
	if d, ok := target["description"].(string); ok && d != "" {
		comp["description"] = d
	}

	// Carry forward embedded SBOM
	if sbom, ok := target["sbom"]; ok && sbom != nil {
		comp["sbom"] = sbom
	}
	if sbomFmt, ok := target["sbomFormat"].(string); ok && sbomFmt != "" {
		comp["sbomFormat"] = sbomFmt
	}
	if ref, ok := target["sbomRef"].(string); ok && ref != "" {
		comp["sbomRef"] = ref
	}

	// Carry forward externalIds
	if ids, ok := target["externalIds"].(map[string]interface{}); ok && len(ids) > 0 {
		comp["externalIds"] = ids
	}

	// Extract labels as targetSelector
	if labels, ok := target["labels"].(map[string]interface{}); ok && len(labels) > 0 {
		selector := make(map[string]interface{}, len(labels))
		for k, v := range labels {
			selector[k] = v
		}
		comp["targetSelector"] = selector
	}

	return comp
}
