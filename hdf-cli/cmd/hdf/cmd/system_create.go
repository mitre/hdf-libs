package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func newSystemCreateCmd() *cobra.Command {
	var (
		fromFile      string
		outputPath    string
		systemName    string
		componentName string
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
  hdf system create --from sbom.cdx.json --component-name "WebTier" -o system.json`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSystemCreate(fromFile, systemName, componentName, outputPath)
		},
	}

	cmd.Flags().StringVar(&fromFile, "from", "", "HDF results file or CycloneDX/SPDX SBOM (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&systemName, "name", "", "System name (default: derived from input)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name (for SBOM input)")

	if err := cmd.MarkFlagRequired("from"); err != nil {
		panic(fmt.Sprintf("failed to mark flag required: %v", err))
	}

	return cmd
}

// targetTypeToComponentType maps HDF target types to system component types.
func targetTypeToComponentType(targetType string) string {
	switch targetType {
	case "host", "containerImage", "containerInstance", "containerPlatform":
		return compTypeCompute
	case "application":
		return compTypeApplication
	case "database":
		return "database"
	case "network":
		return "network"
	case "repository", "artifact":
		return "storage"
	default:
		return "other"
	}
}

func runSystemCreate(fromFile, systemName, componentName, outputPath string) error {
	data, err := os.ReadFile(fromFile) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse input file: %w", err)
	}

	// Detect input type: HDF Results vs CycloneDX SBOM
	if bomFormat, ok := doc["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		return runSystemCreateFromSBOM(doc, fromFile, systemName, componentName, outputPath, sbomFormatCycloneDX)
	}

	// Check for SPDX (has spdxVersion field)
	if _, ok := doc["spdxVersion"]; ok {
		return runSystemCreateFromSBOM(doc, fromFile, systemName, componentName, outputPath, sbomFormatSPDX)
	}

	// Default: treat as HDF Results
	return runSystemCreateFromResults(doc, systemName, outputPath)
}

func runSystemCreateFromResults(results map[string]interface{}, systemName, outputPath string) error {
	// Extract targets
	targetsRaw, ok := results["targets"].([]interface{})
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

	return writeSystemDoc(systemName, components, outputPath)
}

func runSystemCreateFromSBOM(doc map[string]interface{}, filePath, systemName, componentName, outputPath, sbomFormat string) error {
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
		"sbomRef":    filePath,
		"sbomFormat": sbomFormat,
	}

	// Extract version if available
	if ver := extractSBOMComponentVersion(doc, sbomFormat); ver != "" {
		comp["description"] = fmt.Sprintf("%s v%s", componentName, ver)
	}

	fmt.Fprintf(os.Stderr, "Imported %s SBOM as component %q (type: %s)\n", sbomFormat, componentName, compType)
	return writeSystemDoc(systemName, []map[string]interface{}{comp}, outputPath)
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

// extractSBOMComponentType maps SBOM component type to HDF system component type.
func extractSBOMComponentType(doc map[string]interface{}, format string) string {
	if format == sbomFormatCycloneDX {
		if meta, ok := doc["metadata"].(map[string]interface{}); ok {
			if comp, ok := meta["component"].(map[string]interface{}); ok {
				switch comp["type"] {
				case "application", "library", "framework":
					return compTypeApplication
				case "container", "firmware", "device", "operating-system", "platform":
					return compTypeCompute
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

func writeSystemDoc(systemName string, components []map[string]interface{}, outputPath string) error {
	sysDoc := map[string]interface{}{
		"name":             systemName,
		"components":       components,
		"interconnections": []interface{}{},
		"generator": map[string]interface{}{
			"name":    "hdf-cli",
			"version": version,
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}

	output, err := json.MarshalIndent(sysDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize system document: %w", err)
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

// buildComponentFromTarget creates a system component from a results target.
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
