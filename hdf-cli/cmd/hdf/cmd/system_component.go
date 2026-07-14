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
		componentNamePrefix string
		outputPath          string
		embed               bool
		generateComponentID bool
	)

	cmd := &cobra.Command{
		Use:   "add-component <bom|url> --system <doc> [flags]",
		Short: "Add one or more components to a system document from a BOM",
		Long: `Add component(s) to an existing HDF system document by importing metadata
from a BOM. The BOM is a positional file path or URL. A single-subject BOM
(CycloneDX/SPDX SBOM, CycloneDX ML-BOM) adds one component; a multi-subject
SPDX-3 AI/Dataset document adds one correctly-typed component per subject
(aiModel per model, dataset per dataset). Omit --from to auto-detect; pass
--from to assert a BOM format (detected, then required to match — never
force-parsed).

  --from values: cyclonedx | spdx | cyclonedx-mlbom | spdx-ai

Naming: components default to their intrinsic BOM names. Use --component-name to
name a single-component input; use --component-name-prefix to namespace a
multi-subject input (the prefix is prepended to each subject name; unnamed
subjects are numbered). The two flags are mutually exclusive.

Examples:
  hdf system add-component sbom.cdx.json --system system.json --component-name AuthService
  hdf system add-component model.cdx.json --system system.json --from cyclonedx-mlbom
  hdf system add-component ai.spdx.json --system system.json --from spdx-ai --component-name-prefix build42-`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSystemAddComponent(systemFile, args[0], fromFormat, componentName, componentNamePrefix, outputPath, embed, generateComponentID)
		},
	}

	cmd.Flags().StringVar(&systemFile, "system", "", "Existing HDF system document (required)")
	cmd.Flags().StringVar(&fromFormat, "from", "", "Assert the BOM format: cyclonedx | spdx | cyclonedx-mlbom | spdx-ai (default: auto-detect)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Name for a single-component input (default: from BOM metadata)")
	cmd.Flags().StringVar(&componentNamePrefix, "component-name-prefix", "", "Prefix prepended to each subject name for a multi-subject input")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite --system)")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")
	cmd.Flags().BoolVar(&generateComponentID, "generate-component-id", false, "Auto-assign UUID componentId to each added component")

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

	var addNew bool

	cmd := &cobra.Command{
		Use:   "update-component <bom|url> --system <doc> [--component-name <name>] [flags]",
		Short: "Update component(s) in a system document from a refreshed BOM",
		Long: `Update existing component(s) in an HDF system document from a new BOM. The
BOM is a positional file path or URL. Two modes:

  Targeted (--component-name <name>): the named component's boms[] entry and
  metadata are replaced from a single-subject BOM.

  Reconcile (no --component-name): each subject in the BOM is matched to an
  existing component by its stable boms[].uniqueId and that entry is refreshed.
  Unmatched subjects are skipped (pass --add-new to append them); existing
  components absent from the BOM are left unchanged. This refreshes the
  components a prior 'system create'/'add-component' produced from the same
  multi-subject source.

Omit --from to auto-detect; pass --from to assert a BOM format (detected, then
required to match — never force-parsed).

  --from values: cyclonedx | spdx | cyclonedx-mlbom | spdx-ai

Examples:
  hdf system update-component sbom-new.cdx.json --system system.json --component-name WebTier
  hdf system update-component ai.spdx.json --system system.json --add-new`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSystemUpdateComponent(systemFile, args[0], fromFormat, componentName, outputPath, embed, addNew)
		},
	}

	cmd.Flags().StringVar(&systemFile, "system", "", "Existing HDF system document (required)")
	cmd.Flags().StringVar(&fromFormat, "from", "", "Assert the BOM format: cyclonedx | spdx | cyclonedx-mlbom | spdx-ai (default: auto-detect)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Target a single component by name (default: reconcile all subjects by uniqueId)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite --system)")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")
	cmd.Flags().BoolVar(&addNew, "add-new", false, "In reconcile mode, append subjects that match no existing component")

	_ = cmd.MarkFlagRequired("system")

	return cmd
}

// loadComponentBOM performs the shared load-and-validate sequence for the
// component subcommands: load+detect the input BOM (or resolve a URL to a nil
// doc) and apply the --from format assertion (or URL guard). Returns the raw
// bytes (needed to normalize AI-BOMs) alongside the parsed doc and format.
func loadComponentBOM(fromFile, fromFormat string) (data []byte, doc map[string]interface{}, format string, err error) {
	data, doc, format, err = loadBOM(fromFile)
	if err != nil {
		return nil, nil, "", err
	}
	// When --from asserts a format, the detected format must match. A URL input
	// (nil doc) cannot be fetched to verify, so --from is rejected there.
	if doc != nil {
		if err := assertBomFormat(fromFormat, doc); err != nil {
			return nil, nil, "", err
		}
	} else if err := errFormatAssertionOnURL(fromFormat); err != nil {
		return nil, nil, "", err
	}
	return data, doc, format, nil
}

func runSystemAddComponent(systemFile, fromFile, fromFormat, componentName, componentNamePrefix, outputPath string, embed, generateComponentID bool) error {
	if componentName != "" && componentNamePrefix != "" {
		return fmt.Errorf("--component-name and --component-name-prefix are mutually exclusive")
	}

	sysDoc, err := loadSystemDoc(systemFile)
	if err != nil {
		return err
	}
	data, bomDoc, bomFormat, err := loadComponentBOM(fromFile, fromFormat)
	if err != nil {
		return err
	}

	newComps, err := buildAddComponents(data, bomDoc, bomFormat, fromFile, componentName, componentNamePrefix, embed)
	if err != nil {
		return err
	}

	existing, _ := sysDoc["components"].([]interface{})
	warnNameCollisions(existing, newComps)

	for _, comp := range newComps {
		if generateComponentID {
			if _, ok := comp["componentId"]; !ok {
				comp["componentId"] = uuid.New().String()
			}
		}
		existing = append(existing, comp)
	}
	sysDoc["components"] = existing

	if outputPath == "" {
		outputPath = systemFile
	}
	return writeSystemJSON(sysDoc, outputPath, addSummary(newComps, outputPath))
}

// buildAddComponents produces the component(s) to append for add-component,
// applying the naming contract. A URL input (nil doc) yields a single
// passthrough component and requires --component-name.
func buildAddComponents(data []byte, bomDoc map[string]interface{}, bomFormat, fromFile, componentName, componentNamePrefix string, embed bool) ([]map[string]interface{}, error) {
	if bomDoc == nil {
		if componentName == "" {
			return nil, fmt.Errorf("--component-name is required when the input is a URL " +
				"(the remote document can't be read to derive component metadata)")
		}
		comp := map[string]interface{}{
			"name": componentName,
			"type": compTypeApplication,
			"boms": []map[string]interface{}{newSBOMBom(ensureBOMFormat(bomFormat), filepath.ToSlash(fromFile), nil)},
		}
		return []map[string]interface{}{comp}, nil
	}

	comps, err := buildComponentsFromBOM(data, bomDoc, bomFormat, bomComponentBuildOpts{
		fileRef:      filepath.ToSlash(fromFile),
		embed:        embed,
		nameOverride: componentName, // honored only by single-component sub-builders
	})
	if err != nil {
		return nil, err
	}

	if componentName != "" && len(comps) > 1 {
		return nil, fmt.Errorf("--component-name requires exactly one resulting component; this input produced %d. Use --component-name-prefix", len(comps))
	}
	if componentNamePrefix != "" {
		if len(comps) == 1 {
			return nil, fmt.Errorf("--component-name-prefix expects a multi-subject BOM; this input produced a single component. Use --component-name")
		}
		applyNamePrefix(comps, componentNamePrefix)
	}
	return comps, nil
}

func runSystemUpdateComponent(systemFile, fromFile, fromFormat, componentName, outputPath string, embed, addNew bool) error {
	sysDoc, err := loadSystemDoc(systemFile)
	if err != nil {
		return err
	}
	data, bomDoc, bomFormat, err := loadComponentBOM(fromFile, fromFormat)
	if err != nil {
		return err
	}

	components, _ := sysDoc["components"].([]interface{})

	var summary string
	if componentName != "" {
		summary, err = updateComponentTargeted(components, data, bomDoc, bomFormat, fromFile, componentName, embed)
	} else {
		if bomDoc == nil {
			return fmt.Errorf("--component-name is required for a URL input (a remote document cannot be reconciled by subject id)")
		}
		components, summary, err = updateComponentsReconcile(components, data, bomDoc, bomFormat, fromFile, embed, addNew)
	}
	if err != nil {
		return err
	}

	sysDoc["components"] = components
	if outputPath == "" {
		outputPath = systemFile
	}
	return writeSystemJSON(sysDoc, outputPath, fmt.Sprintf("%s in %s", summary, outputPath))
}

// updateComponentTargeted replaces the named component's boms[] entry and
// derived fields from a single-subject BOM. A URL input keeps the passthrough
// path; a multi-subject BOM is rejected (reconcile handles those).
func updateComponentTargeted(components []interface{}, data []byte, bomDoc map[string]interface{}, bomFormat, fromFile, componentName string, embed bool) (string, error) {
	var newComp map[string]interface{}
	if bomDoc == nil {
		newComp = map[string]interface{}{
			"boms": []map[string]interface{}{newSBOMBom(ensureBOMFormat(bomFormat), filepath.ToSlash(fromFile), nil)},
		}
	} else {
		comps, err := buildComponentsFromBOM(data, bomDoc, bomFormat, bomComponentBuildOpts{
			fileRef:      filepath.ToSlash(fromFile),
			embed:        embed,
			nameOverride: componentName,
		})
		if err != nil {
			return "", err
		}
		if len(comps) != 1 {
			return "", fmt.Errorf("--component-name targets a single component, but this input produced %d subjects; omit --component-name to reconcile by subject id", len(comps))
		}
		newComp = comps[0]
	}

	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok || comp["name"] != componentName {
			continue
		}
		comp["boms"] = newComp["boms"]
		// A parsed BOM fully replaces the component's metadata: set the derived
		// fields the refreshed component carries and DELETE any it does not, so
		// updating e.g. an aiModel component with an SBOM leaves no stale
		// modelId/version behind. A URL passthrough carries no derivable metadata,
		// so the component's existing fields are kept untouched.
		if bomDoc != nil {
			for _, k := range []string{"type", "description", "version", "modelId", "datasetId"} {
				if v, ok := newComp[k]; ok {
					comp[k] = v
				} else {
					delete(comp, k)
				}
			}
		}
		return fmt.Sprintf("Component %q updated", componentName), nil
	}
	return "", fmt.Errorf("component %q not found in system document; use 'hdf system add-component' to add it", componentName)
}

// updateComponentsReconcile matches each incoming subject to an existing
// component by boms[].uniqueId and refreshes that entry. Unmatched subjects are
// skipped (or appended with --add-new); existing components absent from the BOM
// are left unchanged with a warning.
func updateComponentsReconcile(components []interface{}, data []byte, bomDoc map[string]interface{}, bomFormat, fromFile string, embed, addNew bool) ([]interface{}, string, error) {
	incoming, err := buildComponentsFromBOM(data, bomDoc, bomFormat, bomComponentBuildOpts{
		fileRef: filepath.ToSlash(fromFile),
		embed:   embed,
	})
	if err != nil {
		return nil, "", err
	}

	matched, added, skipped := 0, 0, 0
	matchedExisting := make(map[int]bool)
	for _, nc := range incoming {
		key := firstBOMUniqueID(nc)
		name, _ := nc["name"].(string)
		if key == "" {
			fmt.Fprintf(os.Stderr, "Warning: subject %q carries no stable id; skipped (reconcile matches by boms[].uniqueId)\n", name)
			skipped++
			continue
		}
		if ci, bi, comp, boms, ok := findComponentByBOMUniqueID(components, key); ok {
			// Refresh is boms-entry-granular by design: swap only the matched
			// entry, not the whole component. A component may carry several BOMs,
			// and the normalized model/dataset refresh lives in this entry.
			// Component-level derived fields are intentionally left alone — the
			// join key (modelId/datasetId == uniqueId) is stable, and the
			// multi-subject builder produces no version/description to refresh.
			boms[bi] = firstBOM(nc)
			comp["boms"] = boms
			matchedExisting[ci] = true
			matched++
			continue
		}
		if addNew {
			components = append(components, nc)
			added++
			fmt.Fprintf(os.Stderr, "Added new subject %q (id %s)\n", name, key)
			continue
		}
		skipped++
		fmt.Fprintf(os.Stderr, "Warning: subject %q (id %s) matches no existing component; skipped (pass --add-new to append)\n", name, key)
	}

	for i, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok || matchedExisting[i] {
			continue
		}
		if firstBOMUniqueID(comp) != "" {
			name, _ := comp["name"].(string)
			fmt.Fprintf(os.Stderr, "Warning: component %q was not present in the updated BOM; left unchanged\n", name)
		}
	}

	if matched == 0 && added == 0 {
		return nil, "", fmt.Errorf("no incoming subject matched an existing component by uniqueId; pass --component-name to target one or --add-new to append")
	}
	return components, fmt.Sprintf("Reconciled components (%d refreshed, %d added, %d skipped)", matched, added, skipped), nil
}

const (
	bomFormatCycloneDX  = "cyclonedx"
	bomFormatSPDX       = "spdx"
	compTypeApplication = "application"
	compTypeAIModel     = "aiModel"
	compTypeDataset     = "dataset"
)

// loadBOM reads and parses a BOM file, or returns nil data/doc with a guessed
// format if the input is a URL. Returns (rawBytes, doc, format, error); the raw
// bytes are needed to normalize AI-BOMs via the shared parser.
func loadBOM(fromRef string) ([]byte, map[string]interface{}, string, error) {
	if isURL(fromRef) {
		return nil, nil, guessFormatFromURI(fromRef), nil
	}

	data, err := os.ReadFile(fromRef) // #nosec G304
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to read BOM file: %w", err)
	}
	if err := shared.ValidateJSONSize(data, "BOM input", int(getMaxFileSize())); err != nil {
		return nil, nil, "", err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse BOM file: %w", err)
	}

	format := detectBOMFormat(doc)
	if format == "" {
		return nil, nil, "", fmt.Errorf("input is not a recognized CycloneDX, SPDX, or AI-BOM document")
	}

	return data, doc, format, nil
}

// loadSystemDoc reads and schema-validates an HDF system document.
func loadSystemDoc(systemFile string) (map[string]interface{}, error) {
	sysData, err := os.ReadFile(systemFile) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read system file: %w", err)
	}
	sysDoc, err := loadAndValidateHDFDoc(sysData, "system")
	if err != nil {
		return nil, fmt.Errorf("system file %s: %w", systemFile, err)
	}
	return sysDoc, nil
}

// detectBOMFormat returns the structurally-detected BOM format
// (cyclonedx, spdx, cyclonedx-ml, spdx-3-ai) or "" for unrecognized input.
func detectBOMFormat(doc map[string]interface{}) string {
	if detected := bom.DetectFormat(doc); detected != nil {
		return detected.Format
	}
	return ""
}

// applyNamePrefix prepends prefix to each component's intrinsic name. Nameless
// components are numbered by a nameless-only counter (prefix1, prefix2, …),
// independent of position, so a named subject never consumes a number.
func applyNamePrefix(comps []map[string]interface{}, prefix string) {
	nameless := 0
	for _, comp := range comps {
		name, _ := comp["name"].(string)
		if name == "" {
			nameless++
			comp["name"] = fmt.Sprintf("%s%d", prefix, nameless)
		} else {
			comp["name"] = prefix + name
		}
	}
}

// warnNameCollisions warns (does not error) when a new component's human-friendly
// name already exists — names are labels, not identity (componentId is), and
// legitimate duplicates exist (e.g. repeated scans of one image).
func warnNameCollisions(existing []interface{}, newComps []map[string]interface{}) {
	names := make(map[string]bool, len(existing))
	for _, c := range existing {
		if comp, ok := c.(map[string]interface{}); ok {
			if name, ok := comp["name"].(string); ok {
				names[name] = true
			}
		}
	}
	for _, comp := range newComps {
		if name, _ := comp["name"].(string); names[name] {
			fmt.Fprintf(os.Stderr, "Warning: a component named %q already exists; adding another with the same name (names are labels, not identity)\n", name)
		}
	}
}

// addSummary builds the stderr summary line for add-component.
func addSummary(newComps []map[string]interface{}, outputPath string) string {
	if len(newComps) == 1 {
		name, _ := newComps[0]["name"].(string)
		return fmt.Sprintf("Component %q added in %s", name, outputPath)
	}
	return fmt.Sprintf("%d components added in %s", len(newComps), outputPath)
}

// firstBOM returns a component's first boms[] entry as a map, handling both the
// freshly-built ([]map) and unmarshalled ([]interface{}) representations.
func firstBOM(comp map[string]interface{}) map[string]interface{} {
	switch boms := comp["boms"].(type) {
	case []map[string]interface{}:
		if len(boms) > 0 {
			return boms[0]
		}
	case []interface{}:
		if len(boms) > 0 {
			if bm, ok := boms[0].(map[string]interface{}); ok {
				return bm
			}
		}
	}
	return nil
}

// firstBOMUniqueID returns the uniqueId of a component's first boms[] entry.
func firstBOMUniqueID(comp map[string]interface{}) string {
	if bm := firstBOM(comp); bm != nil {
		if id, _ := bm["uniqueId"].(string); id != "" {
			return id
		}
	}
	return ""
}

// findComponentByBOMUniqueID locates the component carrying a BOM entry whose
// uniqueId equals key — the reconcile join. It returns the resolved component
// map and its boms slice (already type-checked here) so the caller mutates them
// directly rather than re-asserting components[compIdx] / comp["boms"].
func findComponentByBOMUniqueID(components []interface{}, key string) (compIdx, bomIdx int, comp map[string]interface{}, boms []interface{}, ok bool) {
	for i, c := range components {
		cm, cok := c.(map[string]interface{})
		if !cok {
			continue
		}
		bs, bok := cm["boms"].([]interface{})
		if !bok {
			continue
		}
		for j, b := range bs {
			if bm, ok := b.(map[string]interface{}); ok {
				if id, _ := bm["uniqueId"].(string); id == key {
					return i, j, cm, bs, true
				}
			}
		}
	}
	return 0, 0, nil, nil, false
}

func writeSystemJSON(sysDoc map[string]interface{}, outputPath, message string) error {
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
	fmt.Fprintln(os.Stderr, message)
	return nil
}
