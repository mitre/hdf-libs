package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func newSystemAddComponentCmd() *cobra.Command {
	var (
		systemFile          string
		fromFile            string
		componentName       string
		outputPath          string
		embed               bool
		generateComponentID bool
	)

	cmd := &cobra.Command{
		Use:   "add-component",
		Short: "Add a component to an existing system document from an SBOM",
		Long: `Add a new component to an existing HDF system document by importing
metadata from a CycloneDX or SPDX SBOM file.

Examples:
  hdf system add-component --system system.json --from sbom.cdx.json --component-name AuthService
  hdf system add-component --system system.json --from sbom.cdx.json --component-name AuthService --embed`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSystemAddComponent(systemFile, fromFile, componentName, outputPath, embed, generateComponentID)
		},
	}

	cmd.Flags().StringVar(&systemFile, "system", "", "Existing HDF system document (required)")
	cmd.Flags().StringVar(&fromFile, "from", "", "CycloneDX or SPDX SBOM file (required)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name (default: from SBOM metadata)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite --system)")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")
	cmd.Flags().BoolVar(&generateComponentID, "generate-component-id", false, "Auto-assign UUID componentId to the new component")

	_ = cmd.MarkFlagRequired("system")
	_ = cmd.MarkFlagRequired("from")

	return cmd
}

func newSystemUpdateComponentCmd() *cobra.Command {
	var (
		systemFile    string
		fromFile      string
		componentName string
		outputPath    string
		embed         bool
	)

	cmd := &cobra.Command{
		Use:   "update-component",
		Short: "Update a component's SBOM reference in a system document",
		Long: `Update an existing component in an HDF system document with a new
CycloneDX or SPDX SBOM reference. The component's sbomRef and metadata
are updated from the new SBOM.

Examples:
  hdf system update-component --system system.json --component-name WebTier --from sbom-new.cdx.json
  hdf system update-component --system system.json --component-name WebTier --from sbom-new.cdx.json --embed`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSystemUpdateComponent(systemFile, fromFile, componentName, outputPath, embed)
		},
	}

	cmd.Flags().StringVar(&systemFile, "system", "", "Existing HDF system document (required)")
	cmd.Flags().StringVar(&fromFile, "from", "", "CycloneDX or SPDX SBOM file (required)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name to update (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite --system)")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")

	_ = cmd.MarkFlagRequired("system")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("component-name")

	return cmd
}

func runSystemAddComponent(systemFile, fromFile, componentName, outputPath string, embed, generateComponentID bool) error {
	// Load existing system
	sysData, err := os.ReadFile(systemFile) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to read system file: %w", err)
	}
	sysDoc, err := loadAndValidateHDFDoc(sysData, "system")
	if err != nil {
		return fmt.Errorf("system file %s: %w", systemFile, err)
	}

	// Load and parse SBOM (or handle URL)
	sbomDoc, sbomFormat, err := loadSBOM(fromFile)
	if err != nil {
		return err
	}

	// Extract component name
	if componentName == "" {
		if sbomDoc != nil {
			componentName = extractSBOMComponentName(sbomDoc, sbomFormat)
		}
	}
	if componentName == "" {
		return fmt.Errorf("cannot determine component name; use --component-name to specify")
	}

	// Check for duplicate
	components, _ := sysDoc["components"].([]interface{})
	for _, c := range components {
		if comp, ok := c.(map[string]interface{}); ok {
			if comp["name"] == componentName {
				return fmt.Errorf("component %q already exists; use 'hdf system update-component' to update it", componentName)
			}
		}
	}

	// Build new component
	compType := compTypeApplication
	if sbomDoc != nil {
		compType = extractSBOMComponentType(sbomDoc, sbomFormat)
	}
	comp := map[string]interface{}{
		"name":    componentName,
		"type":    compType,
		"sbomRef": filepath.ToSlash(fromFile), // schema requires uri-reference; Windows backslashes are invalid
	}
	if sbomFormat != "" {
		comp["sbomFormat"] = sbomFormat
	}
	if sbomDoc != nil {
		if ver := extractSBOMComponentVersion(sbomDoc, sbomFormat); ver != "" {
			comp["description"] = fmt.Sprintf("%s v%s", componentName, ver)
		}
		if embed {
			comp["sbom"] = sbomDoc
		}
	}

	// Stamp componentId if requested
	if generateComponentID {
		comp["componentId"] = uuid.New().String()
	}

	// Append to components
	components = append(components, comp)
	sysDoc["components"] = components

	// Write output
	if outputPath == "" {
		outputPath = systemFile
	}
	return writeSystemJSON(sysDoc, outputPath, componentName, "added")
}

func runSystemUpdateComponent(systemFile, fromFile, componentName, outputPath string, embed bool) error {
	// Load existing system
	sysData, err := os.ReadFile(systemFile) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to read system file: %w", err)
	}
	sysDoc, err := loadAndValidateHDFDoc(sysData, "system")
	if err != nil {
		return fmt.Errorf("system file %s: %w", systemFile, err)
	}

	// Load and parse SBOM (or handle URL)
	sbomDoc, sbomFormat, err := loadSBOM(fromFile)
	if err != nil {
		return err
	}

	// Find and update the component
	components, _ := sysDoc["components"].([]interface{})
	found := false
	for i, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if comp["name"] == componentName {
			comp["sbomRef"] = filepath.ToSlash(fromFile) // schema requires uri-reference
			if sbomFormat != "" {
				comp["sbomFormat"] = sbomFormat
			}
			if sbomDoc != nil {
				if ver := extractSBOMComponentVersion(sbomDoc, sbomFormat); ver != "" {
					comp["description"] = fmt.Sprintf("%s v%s", componentName, ver)
				}
				if embed {
					comp["sbom"] = sbomDoc
				}
			}
			components[i] = comp
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("component %q not found in system document; use 'hdf system add-component' to add it", componentName)
	}

	sysDoc["components"] = components

	// Write output
	if outputPath == "" {
		outputPath = systemFile
	}
	return writeSystemJSON(sysDoc, outputPath, componentName, "updated")
}

const (
	sbomFormatCycloneDX = "cyclonedx"
	sbomFormatSPDX      = "spdx"
	compTypeApplication = "application"
)

// loadSBOM reads and parses an SBOM file, or returns nil doc with a guessed
// format if the input is a URL. Returns (doc, format, error).
func loadSBOM(fromRef string) (map[string]interface{}, string, error) {
	if isURL(fromRef) {
		return nil, guessFormatFromURI(fromRef), nil
	}

	data, err := os.ReadFile(fromRef) // #nosec G304
	if err != nil {
		return nil, "", fmt.Errorf("failed to read SBOM file: %w", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	format := detectSBOMFormat(doc)
	if format == "" {
		return nil, "", fmt.Errorf("input is not a recognized CycloneDX or SPDX SBOM")
	}

	return doc, format, nil
}

// detectSBOMFormat returns sbomFormatCycloneDX, sbomFormatSPDX, or "" for unrecognized input.
func detectSBOMFormat(doc map[string]interface{}) string {
	if bomFmt, ok := doc["bomFormat"].(string); ok && bomFmt == "CycloneDX" {
		return sbomFormatCycloneDX
	}
	if _, ok := doc["spdxVersion"]; ok {
		return sbomFormatSPDX
	}
	return ""
}

func writeSystemJSON(sysDoc map[string]interface{}, outputPath, componentName, action string) error {
	output, err := json.MarshalIndent(sysDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize system document: %w", err)
	}

	if err := validateHDFOutput(output); err != nil {
		return fmt.Errorf("system document failed validation before write: %w", err)
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil {
		return fmt.Errorf("failed to write system document: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Component %q %s in %s\n", componentName, action, outputPath)
	return nil
}
