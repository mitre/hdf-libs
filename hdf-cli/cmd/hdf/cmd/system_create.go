package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	bom "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/bom"
	"github.com/spf13/cobra"
)

func newSystemCreateCmd() *cobra.Command {
	var (
		fromFormat          string
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
		Use:   "create <bom|url> [flags]",
		Short: "Bootstrap an HDF system document from a results file or SBOM",
		Long: `Generate an HDF system document by extracting targets and baselines
from an HDF results file, or by importing component metadata from a
CycloneDX/SPDX SBOM, AI-BOM, or SPDX 3.0 AI/Dataset document. The input is a
positional file path or URL. Omit --from to auto-detect the input format;
pass --from to assert a specific BOM format (the input is detected, then the
detected format must match — it is never force-parsed). This differs from
` + "`hdf convert --from`" + `, which selects a parser: here --from only VERIFIES
the auto-detected format.

  --from values: cyclonedx | spdx | cyclonedx-mlbom | spdx-ai

Examples:
  hdf system create results.json
  hdf system create results.json -o system.json
  hdf system create results.json --name "Portal Prod" -o system.json
  hdf system create sbom.cdx.json --from cyclonedx --component-name "WebTier" -o system.json
  hdf system create model.cdx.json --from cyclonedx-mlbom -o system.json
  hdf system create results.json --owner team@agency.gov --description "Prod portal"`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			opts := systemCreateOpts{
				fromFile:            args[0],
				fromFormat:          fromFormat,
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

	cmd.Flags().StringVar(&fromFormat, "from", "", "Verify the detected BOM format: cyclonedx | spdx | cyclonedx-mlbom | spdx-ai (default: auto-detect; never force-parses)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&systemName, "name", "", "System name (default: derived from input)")
	cmd.Flags().StringVar(&componentName, "component-name", "", "Component name (for SBOM input)")
	cmd.Flags().StringVar(&ownerEmail, "owner", "", "System owner (email or plain text name)")
	cmd.Flags().StringVar(&systemID, "system-id", "", "System UUID (auto-generated if omitted)")
	cmd.Flags().StringVar(&description, "description", "", "System description")
	cmd.Flags().BoolVar(&embed, "embed", false, "Embed referenced data (e.g. SBOM) inline instead of storing a reference")
	cmd.Flags().BoolVar(&generateComponentID, "generate-component-id", false, "Auto-assign UUID componentId to each component")

	return cmd
}

// bomFormatAliases lists the valid --from format-assertion aliases shared by the
// `hdf system` command group. One canonical spelling per format; accepted ==
// advertised.
var bomFormatAliases = []string{"cyclonedx", "spdx", "cyclonedx-mlbom", "spdx-ai"}

// assertBomFormat verifies that doc's structurally-detected BOM format matches
// the requested --from alias. An empty alias performs no assertion (auto-detect).
// It never force-parses: on a mismatch, an unrecognized alias, or an
// undetectable input it returns an error rather than coercing the input.
func assertBomFormat(alias string, doc map[string]interface{}) error {
	if alias == "" {
		return nil
	}
	return assertBomFormatDetected(alias, bom.DetectFormat(doc))
}

// assertBomFormatDetected is assertBomFormat against an already-detected format,
// letting callers that have run bom.DetectFormat once avoid re-detecting.
func assertBomFormatDetected(alias string, detected *bom.FormatDetection) error {
	if alias == "" {
		return nil
	}
	detectedName := "unrecognized (not a BOM)"
	if detected != nil {
		detectedName = detected.Format
	}
	switch alias {
	case "cyclonedx":
		if detected == nil || detected.Format != bom.FormatCycloneDX {
			return bomFormatMismatch(alias, "a plain CycloneDX SBOM", detectedName)
		}
	case "spdx":
		if detected == nil || detected.Format != bom.FormatSPDX {
			return bomFormatMismatch(alias, "a plain SPDX SBOM", detectedName)
		}
	case "cyclonedx-mlbom":
		if detected == nil || detected.Format != bom.FormatCycloneDXML {
			return bomFormatMismatch(alias, "a CycloneDX ML-BOM (a machine-learning-model component)", detectedName)
		}
	case "spdx-ai":
		if detected == nil || detected.Format != bom.FormatSPDX3AI {
			return bomFormatMismatch(alias, "an SPDX 3.0 AI/Dataset document", detectedName)
		}
	default:
		return fmt.Errorf("unknown --from format %q; valid formats: %s", alias, strings.Join(bomFormatAliases, ", "))
	}
	return nil
}

func bomFormatMismatch(alias, expected, detected string) error {
	return fmt.Errorf("--from %s expects %s, but the input was detected as %q; "+
		"pass the matching --from value or omit --from to auto-detect", alias, expected, detected)
}

// errFormatAssertionOnURL rejects `--from <format>` when the input is a URL: the
// document is referenced, not fetched, so its format cannot be verified and a
// blind assertion could mislabel a remote BOM. Returns nil when no --from is set.
func errFormatAssertionOnURL(alias string) error {
	if alias == "" {
		return nil
	}
	return fmt.Errorf("cannot assert --from %s on a URL input: the document is referenced, "+
		"not fetched, so its format cannot be verified; omit --from for URL references", alias)
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
	fromFormat          string
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
	// A URL input is referenced, not fetched: it can't be read to derive
	// component metadata, verify a --from assertion, or embed its content.
	if isURL(opts.fromFile) {
		if err := errFormatAssertionOnURL(opts.fromFormat); err != nil {
			return err
		}
		if opts.embed {
			return fmt.Errorf("--embed cannot embed a URL input: the remote document is referenced, " +
				"not fetched; drop --embed or pass a local file")
		}
		return runSystemCreateFromSBOMRef(opts, opts.fromFile)
	}

	data, err := os.ReadFile(opts.fromFile) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}
	if err := shared.ValidateJSONSize(data, "system-create input", int(getMaxFileSize())); err != nil {
		return err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse input file: %w", err)
	}

	// Detect the BOM format once, then reuse it for the --from assertion and the
	// routing switch below rather than re-probing the document. An ML-BOM wins
	// over plain CycloneDX by detector precedence, so the AI-model path is reached
	// before the plain-SBOM path and the model extension is normalized.
	detected := bom.DetectFormat(doc)
	if err := assertBomFormatDetected(opts.fromFormat, detected); err != nil {
		return err
	}

	if detected != nil {
		switch detected.Format {
		case bom.FormatCycloneDXML:
			return runSystemCreateFromAIModelBOM(data, doc, opts)
		case bom.FormatCycloneDX:
			return runSystemCreateFromSBOM(doc, opts.fromFile, opts.systemName, opts.componentName, opts.outputPath, bomFormatCycloneDX, opts)
		case bom.FormatSPDX:
			return runSystemCreateFromSBOM(doc, opts.fromFile, opts.systemName, opts.componentName, opts.outputPath, bomFormatSPDX, opts)
		case bom.FormatSPDX3AI:
			return runSystemCreateFromSPDX3AIBOM(data, doc, opts)
		}
	}

	// Default: treat as HDF Results
	return runSystemCreateFromResults(doc, opts.systemName, opts.outputPath, opts)
}

// runSystemCreateFromSPDX3AIBOM builds a system document from an SPDX 3.0
// AI/Dataset document, emitting one thin aiModel component per ai_AIPackage and
// one thin dataset component per dataset_DatasetPackage, each carrying its
// normalized spdx-3-ai BOM in boms[]. Partial-fidelity: the shared parser lifts
// only clean fields and carries the raw element via passthrough — never
// fabricating fields the source omits.
func runSystemCreateFromSPDX3AIBOM(data []byte, doc map[string]interface{}, opts systemCreateOpts) error {
	components, err := buildSPDX3Components(data, doc)
	if err != nil {
		return err
	}

	systemName := opts.systemName
	if systemName == "" {
		firstName, _ := components[0]["name"].(string)
		systemName = firstName + "-system"
	}

	models, datasets := countComponentKinds(components)
	fmt.Fprintf(os.Stderr, "Imported SPDX-3 AI/Dataset document (%d aiModel, %d dataset components)\n", models, datasets)
	return writeSystemDoc(systemName, components, opts.outputPath, opts)
}

// runSystemCreateFromSBOMRef creates a system document from a remote SBOM URL.
// The remote document is referenced, not fetched, so component metadata can't be
// derived from it — --component-name must be supplied. All system-level opts
// (--owner/--description/--system-id/--generate-component-id) still apply.
func runSystemCreateFromSBOMRef(opts systemCreateOpts, sbomURI string) error {
	if opts.componentName == "" {
		return fmt.Errorf("--component-name is required when the input is a URL " +
			"(the remote document can't be read to derive component metadata)")
	}

	systemName := opts.systemName
	if systemName == "" {
		systemName = opts.componentName + "-system"
	}

	// Guess format from URL extension; format is schema-required on the BOM entry.
	// A hint-less URL can't be verified (the document is not fetched), so warn
	// that the defaulted format is unverified.
	guessed := guessFormatFromURI(sbomURI)
	if guessed == "" {
		fmt.Fprintf(os.Stderr, "Warning: could not infer BOM format from URL %q; defaulting to %q "+
			"(unverified — the remote document is not fetched)\n", sbomURI, bomFormatCycloneDX)
	}
	bomFormat := ensureBOMFormat(guessed)

	comp := map[string]interface{}{
		"name": opts.componentName,
		"type": compTypeApplication,
		"boms": []map[string]interface{}{newSBOMBom(bomFormat, sbomURI, nil)},
	}

	fmt.Fprintf(os.Stderr, "Created component %q from URI (type: %s)\n", opts.componentName, compTypeApplication)
	fmt.Fprintf(os.Stderr, "Note: component type defaulted to %q; edit the system document to correct if needed\n", compTypeApplication)
	return writeSystemDoc(systemName, []map[string]interface{}{comp}, opts.outputPath, opts)
}

// newSBOMBom builds a passthrough SBOM entry for a component's boms[] array,
// per the generalized Bom schema (ADR-0001). bomType and format are required;
// ref carries the manifest by reference and document carries it embedded.
func newSBOMBom(format, ref string, document map[string]interface{}) map[string]interface{} {
	bom := map[string]interface{}{
		"bomType": "sbom",
		"format":  format,
	}
	if ref != "" {
		bom["ref"] = ref
	}
	if document != nil {
		bom["document"] = document
	}
	return bom
}

// ensureBOMFormat guarantees a non-empty format (schema-required on the BOM
// entry). When the format can't be identified, it falls back to the ecosystem's
// predominant format rather than a file extension — a generic ".json" extension
// is not a BOM format and would leak a bogus value into the emitted document.
func ensureBOMFormat(format string) string {
	if format != "" {
		return format
	}
	return bomFormatCycloneDX
}

// guessFormatFromURI attempts to determine SBOM format from the URI extension.
func guessFormatFromURI(uri string) string {
	lower := strings.ToLower(uri)
	if strings.Contains(lower, ".cdx.") || strings.Contains(lower, "cyclonedx") {
		return bomFormatCycloneDX
	}
	if strings.Contains(lower, ".spdx.") || strings.Contains(lower, "spdx") {
		return bomFormatSPDX
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

func runSystemCreateFromSBOM(doc map[string]interface{}, filePath, systemName, componentName, outputPath, bomFormat string, opts systemCreateOpts) error {
	comp, err := buildSBOMComponent(doc, bomFormat, bomComponentBuildOpts{
		fileRef:      filepath.ToSlash(filePath), // schema requires uri-reference; Windows backslashes are invalid
		embed:        opts.embed,
		nameOverride: componentName,
	})
	if err != nil {
		return err
	}

	name, _ := comp["name"].(string)
	if systemName == "" {
		systemName = name + "-system"
	}

	fmt.Fprintf(os.Stderr, "Imported %s SBOM as component %q (type: %s)\n", bomFormat, name, comp["type"])
	return writeSystemDoc(systemName, []map[string]interface{}{comp}, outputPath, opts)
}

// runSystemCreateFromAIModelBOM builds a system document whose single component
// is a thin aiModel component carrying the normalized ai-model BOM in boms[].
// Unlike the SBOM path (which passes the manifest through by reference), this
// uses the shared parser to lift the model extension (modelArchitecture etc.)
// into a schema-valid, normalized ai-model BOM — never fabricating fields the
// source omits.
func runSystemCreateFromAIModelBOM(data []byte, doc map[string]interface{}, opts systemCreateOpts) error {
	comp, err := buildAIModelComponent(data, doc, opts.componentName)
	if err != nil {
		return err
	}

	name, _ := comp["name"].(string)
	systemName := opts.systemName
	if systemName == "" {
		systemName = name + "-system"
	}

	fmt.Fprintf(os.Stderr, "Imported CycloneDX ML-BOM as aiModel component %q\n", name)
	return writeSystemDoc(systemName, []map[string]interface{}{comp}, opts.outputPath, opts)
}

// structToMap round-trips a value through JSON into a generic map so it can be
// embedded in the system document's boms[] array.
func structToMap(v interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// extractMLModelComponent returns the CycloneDX machine-learning-model component,
// falling back to metadata.component when no dedicated model component is present.
func extractMLModelComponent(doc map[string]interface{}) map[string]interface{} {
	if comps, ok := doc["components"].([]interface{}); ok {
		for _, c := range comps {
			if cm, ok := c.(map[string]interface{}); ok && cm["type"] == "machine-learning-model" {
				return cm
			}
		}
	}
	if meta, ok := doc["metadata"].(map[string]interface{}); ok {
		if comp, ok := meta["component"].(map[string]interface{}); ok {
			return comp
		}
	}
	return nil
}

// extractMLModelName gets the model component's name.
func extractMLModelName(doc map[string]interface{}) string {
	if c := extractMLModelComponent(doc); c != nil {
		if name, ok := c["name"].(string); ok {
			return name
		}
	}
	return ""
}

// extractMLModelID gets a provider/registry identifier for the model: the purl
// when present, else the bom-ref.
func extractMLModelID(doc map[string]interface{}) string {
	if c := extractMLModelComponent(doc); c != nil {
		if purl, ok := c["purl"].(string); ok && purl != "" {
			return purl
		}
		if ref, ok := c["bom-ref"].(string); ok && ref != "" {
			return ref
		}
	}
	return ""
}

// extractMLModelVersion gets the model component's version.
func extractMLModelVersion(doc map[string]interface{}) string {
	if c := extractMLModelComponent(doc); c != nil {
		if ver, ok := c["version"].(string); ok {
			return ver
		}
	}
	return ""
}

// extractSBOMComponentName gets the top-level component name from a CycloneDX or SPDX SBOM.
func extractSBOMComponentName(doc map[string]interface{}, format string) string {
	switch format {
	case bomFormatCycloneDX:
		if meta, ok := doc["metadata"].(map[string]interface{}); ok {
			if comp, ok := meta["component"].(map[string]interface{}); ok {
				if name, ok := comp["name"].(string); ok {
					return name
				}
			}
		}
	case bomFormatSPDX:
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
	if format == bomFormatCycloneDX {
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
	if format == bomFormatCycloneDX {
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

	// Carry forward attached BOMs (SBOM, ai-model, dataset, ...)
	if boms, ok := target["boms"]; ok && boms != nil {
		comp["boms"] = boms
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
