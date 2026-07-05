package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	bom "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/bom"
	"github.com/spf13/cobra"
)

func newSystemAddComponentCmd() *cobra.Command {
	var (
		systemFile          string
		fromFormat          string
		componentName       string
		outputPath          string
		embed               bool
		generateComponentID bool
	)

	cmd := &cobra.Command{
		Use:   "add-component <sbom|url> --system <doc> [flags]",
		Short: "Add a component to an existing system document from an SBOM",
		Long: `Add a new component to an existing HDF system document by importing
metadata from a CycloneDX or SPDX SBOM. The SBOM is a positional file path or
URL. Omit --from to auto-detect; pass --from to assert a BOM format (detected,
then required to match — never force-parsed).

  --from values: cyclonedx | spdx (AI-BOMs are rejected here; import them with 'hdf system create')

Examples:
  hdf system add-component sbom.cdx.json --system system.json --component-name AuthService
  hdf system add-component sbom.cdx.json --system system.json --from cyclonedx --component-name AuthService --embed`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSystemAddComponent(systemFile, args[0], fromFormat, componentName, outputPath, embed, generateComponentID)
		},
	}

	cmd.Flags().StringVar(&systemFile, "system", "", "Existing HDF system document (required)")
	cmd.Flags().StringVar(&fromFormat, "from", "", "Assert the SBOM's format: cyclonedx | spdx (default: auto-detect)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name (default: from SBOM metadata)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite --system)")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")
	cmd.Flags().BoolVar(&generateComponentID, "generate-component-id", false, "Auto-assign UUID componentId to the new component")

	_ = cmd.MarkFlagRequired("system")

	return cmd
}

func newSystemUpdateComponentCmd() *cobra.Command {
	var (
		systemFile    string
		fromFormat    string
		componentName string
		outputPath    string
		embed         bool
	)

	cmd := &cobra.Command{
		Use:   "update-component <sbom|url> --system <doc> --component-name <name> [flags]",
		Short: "Update a component's SBOM reference in a system document",
		Long: `Update an existing component in an HDF system document with a new
CycloneDX or SPDX SBOM reference. The SBOM is a positional file path or URL.
The component's boms[] entry and metadata are updated from the new SBOM. Omit
--from to auto-detect; pass --from to assert a BOM format (detected, then
required to match — never force-parsed).

  --from values: cyclonedx | spdx (AI-BOMs are rejected here; import them with 'hdf system create')

Examples:
  hdf system update-component sbom-new.cdx.json --system system.json --component-name WebTier
  hdf system update-component sbom-new.cdx.json --system system.json --component-name WebTier --from cyclonedx --embed`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSystemUpdateComponent(systemFile, args[0], fromFormat, componentName, outputPath, embed)
		},
	}

	cmd.Flags().StringVar(&systemFile, "system", "", "Existing HDF system document (required)")
	cmd.Flags().StringVar(&fromFormat, "from", "", "Assert the SBOM's format: cyclonedx | spdx (default: auto-detect)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name to update (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite --system)")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")

	_ = cmd.MarkFlagRequired("system")
	_ = cmd.MarkFlagRequired("component-name")

	return cmd
}

// loadComponentBOM performs the shared load-and-validate sequence for the
// component subcommands: load+detect the input BOM (or resolve a URL to a nil
// doc), apply the --from format assertion (or URL guard), and reject AI-BOM
// inputs. subcommand names the caller for the AI-BOM rejection message.
func loadComponentBOM(subcommand, fromFile, fromFormat string) (map[string]interface{}, string, error) {
	bomDoc, bomFormat, err := loadBOM(fromFile)
	if err != nil {
		return nil, "", err
	}
	// When --from asserts a format, the detected format must match.
	if bomDoc != nil {
		if err := assertBomFormat(fromFormat, bomDoc); err != nil {
			return nil, "", err
		}
	} else if err := errFormatAssertionOnURL(fromFormat); err != nil {
		return nil, "", err
	}
	if err := rejectAIBOMComponentInput(subcommand, bomDoc); err != nil {
		return nil, "", err
	}
	return bomDoc, bomFormat, nil
}

func runSystemAddComponent(systemFile, fromFile, fromFormat, componentName, outputPath string, embed, generateComponentID bool) error {
	// Load existing system
	sysData, err := os.ReadFile(systemFile) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to read system file: %w", err)
	}
	sysDoc, err := loadAndValidateHDFDoc(sysData, "system")
	if err != nil {
		return fmt.Errorf("system file %s: %w", systemFile, err)
	}

	// Load, validate, and AI-BOM-guard the input BOM (shared with update-component).
	bomDoc, bomFormat, err := loadComponentBOM("add-component", fromFile, fromFormat)
	if err != nil {
		return err
	}

	// Extract component name
	if componentName == "" {
		if bomDoc != nil {
			componentName = extractSBOMComponentName(bomDoc, bomFormat)
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
	if bomDoc != nil {
		compType = extractSBOMComponentType(bomDoc, bomFormat)
	}
	ref := filepath.ToSlash(fromFile) // schema requires uri-reference; Windows backslashes are invalid
	comp := map[string]interface{}{
		"name": componentName,
		"type": compType,
	}
	var embedDoc map[string]interface{}
	if bomDoc != nil {
		if ver := extractSBOMComponentVersion(bomDoc, bomFormat); ver != "" {
			comp["description"] = fmt.Sprintf("%s v%s", componentName, ver)
		}
		if embed {
			embedDoc = bomDoc
		}
	}
	comp["boms"] = []map[string]interface{}{newSBOMBom(ensureBOMFormat(bomFormat), ref, embedDoc)}

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

func runSystemUpdateComponent(systemFile, fromFile, fromFormat, componentName, outputPath string, embed bool) error {
	// Load existing system
	sysData, err := os.ReadFile(systemFile) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to read system file: %w", err)
	}
	sysDoc, err := loadAndValidateHDFDoc(sysData, "system")
	if err != nil {
		return fmt.Errorf("system file %s: %w", systemFile, err)
	}

	// Load, validate, and AI-BOM-guard the input BOM (shared with add-component).
	bomDoc, bomFormat, err := loadComponentBOM("update-component", fromFile, fromFormat)
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
			ref := filepath.ToSlash(fromFile) // schema requires uri-reference
			var embedDoc map[string]interface{}
			if bomDoc != nil {
				if ver := extractSBOMComponentVersion(bomDoc, bomFormat); ver != "" {
					comp["description"] = fmt.Sprintf("%s v%s", componentName, ver)
				}
				if embed {
					embedDoc = bomDoc
				}
			}
			comp["boms"] = []map[string]interface{}{newSBOMBom(ensureBOMFormat(bomFormat), ref, embedDoc)}
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
	bomFormatCycloneDX  = "cyclonedx"
	bomFormatSPDX       = "spdx"
	compTypeApplication = "application"
	compTypeAIModel     = "aiModel"
	compTypeDataset     = "dataset"
)

// loadBOM reads and parses an SBOM file, or returns nil doc with a guessed
// format if the input is a URL. Returns (doc, format, error).
func loadBOM(fromRef string) (map[string]interface{}, string, error) {
	if isURL(fromRef) {
		return nil, guessFormatFromURI(fromRef), nil
	}

	data, err := os.ReadFile(fromRef) // #nosec G304
	if err != nil {
		return nil, "", fmt.Errorf("failed to read SBOM file: %w", err)
	}
	if err := shared.ValidateJSONSize(data, "SBOM input", int(getMaxFileSize())); err != nil {
		return nil, "", err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	format := detectBOMFormat(doc)
	if format == "" {
		return nil, "", fmt.Errorf("input is not a recognized CycloneDX or SPDX SBOM")
	}

	return doc, format, nil
}

// detectBOMFormat returns the structurally-detected BOM format
// (cyclonedx, spdx, cyclonedx-ml, spdx-3-ai) or "" for unrecognized input.
func detectBOMFormat(doc map[string]interface{}) string {
	if detected := bom.DetectFormat(doc); detected != nil {
		return detected.Format
	}
	return ""
}

// rejectAIBOMComponentInput refuses AI-BOM inputs on the component subcommands,
// which currently model every BOM as an SBOM component. Ingesting an AI-BOM here
// would mislabel it (bomType=sbom on a model/dataset), so we redirect to
// `hdf system create` (which produces correctly-typed aiModel/dataset components)
// until component ingestion is generalized to any BOM type (hdf-libs-opk1).
//
// URL inputs arrive as a nil doc (the remote document is referenced, not fetched)
// and therefore escape this guard: a remote AI-BOM cannot be detected here. Full
// remote-AI-BOM handling is tracked in hdf-libs-opk1.
func rejectAIBOMComponentInput(subcommand string, doc map[string]interface{}) error {
	if doc == nil {
		return nil
	}
	detected := bom.DetectFormat(doc)
	if detected == nil {
		return nil
	}
	switch detected.Format {
	case bom.FormatCycloneDXML:
		return fmt.Errorf("system %s does not yet support AI-BOM inputs (CycloneDX ML-BOM); "+
			"use `hdf system create <file> --from cyclonedx-mlbom` to import the model", subcommand)
	case bom.FormatSPDX3AI:
		return fmt.Errorf("system %s does not yet support AI-BOM inputs (SPDX-3 AI/Dataset); "+
			"use `hdf system create <file> --from spdx-ai` to import the models/datasets", subcommand)
	}
	return nil
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
