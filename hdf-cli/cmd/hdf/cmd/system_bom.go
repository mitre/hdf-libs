package cmd

import (
	"fmt"

	bom "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/bom"
)

// bomComponentBuildOpts controls how buildComponentsFromBOM emits components.
type bomComponentBuildOpts struct {
	// fileRef is the uri-reference stored in a passthrough SBOM's boms[].ref.
	fileRef string
	// embed carries the raw manifest inline in boms[].document (SBOM passthrough).
	embed bool
	// nameOverride sets the component name when the BOM yields exactly ONE
	// component (CycloneDX/SPDX SBOM or CycloneDX ML-BOM). It is ignored for
	// multi-subject SPDX-3 documents, whose components keep their subject names.
	nameOverride string
}

// buildComponentsFromBOM turns a parsed BOM document into the HDF component(s) it
// describes, WITHOUT mutating any system document. A single-subject BOM
// (CycloneDX/SPDX SBOM, CycloneDX ML-BOM) yields one component; a multi-subject
// SPDX-3 AI/Dataset document yields one component per subject (aiModel per model,
// dataset per dataset). Shared by `system create` and the component subcommands
// so the two entry points build components identically (ADR-0001).
func buildComponentsFromBOM(data []byte, doc map[string]interface{}, bomFormat string, opts bomComponentBuildOpts) ([]map[string]interface{}, error) {
	var (
		comps []map[string]interface{}
		err   error
	)
	switch bomFormat {
	case bom.FormatCycloneDXML:
		var comp map[string]interface{}
		if comp, err = buildAIModelComponent(data, doc, opts.nameOverride); err == nil {
			comps = []map[string]interface{}{comp}
		}
	case bom.FormatSPDX3AI:
		comps, err = buildSPDX3Components(data, doc)
	case bom.FormatCycloneDX, bom.FormatSPDX:
		var comp map[string]interface{}
		if comp, err = buildSBOMComponent(doc, bomFormat, opts); err == nil {
			comps = []map[string]interface{}{comp}
		}
	default:
		return nil, fmt.Errorf("unsupported BOM format %q for component ingestion", bomFormat)
	}
	if err != nil {
		return nil, err
	}
	// A single-component result honors nameOverride uniformly. The SBOM/ML-BOM
	// sub-builders already applied it internally (their description derives from
	// the final name); this additionally covers a single-subject SPDX-3 document,
	// where the subject builder does not take an override.
	if opts.nameOverride != "" && len(comps) == 1 {
		comps[0]["name"] = opts.nameOverride
	}
	return comps, nil
}

// buildSBOMComponent builds a single passthrough SBOM component (CycloneDX or
// SPDX). The manifest is carried by reference (boms[].ref) and, when embed is
// set, also embedded (boms[].document) — never normalized into packages[].
func buildSBOMComponent(doc map[string]interface{}, bomFormat string, opts bomComponentBuildOpts) (map[string]interface{}, error) {
	name := opts.nameOverride
	if name == "" {
		name = extractSBOMComponentName(doc, bomFormat)
	}
	if name == "" {
		return nil, fmt.Errorf("cannot determine component name from SBOM; use --component-name to specify")
	}

	var embedDoc map[string]interface{}
	if opts.embed {
		embedDoc = doc
	}

	comp := map[string]interface{}{
		"name": name,
		"type": extractSBOMComponentType(doc, bomFormat),
		"boms": []map[string]interface{}{newSBOMBom(bomFormat, opts.fileRef, embedDoc)},
	}
	if ver := extractSBOMComponentVersion(doc, bomFormat); ver != "" {
		comp["description"] = fmt.Sprintf("%s v%s", name, ver)
	}
	return comp, nil
}

// buildAIModelComponent builds a single thin aiModel component carrying the
// normalized ai-model BOM (modelArchitecture etc.) lifted by the shared parser —
// never fabricating fields the source omits. nameOverride, when set, names the
// component; otherwise the model component's own name is used.
func buildAIModelComponent(data []byte, doc map[string]interface{}, nameOverride string) (map[string]interface{}, error) {
	result, err := bom.ParseBom(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI-model BOM: %w", err)
	}

	name := nameOverride
	if name == "" {
		name = extractMLModelName(doc)
	}
	if name == "" {
		return nil, fmt.Errorf("cannot determine model name from AI-BOM; use --component-name to specify")
	}

	bomMap, err := structToMap(result.Normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize normalized AI-model BOM: %w", err)
	}

	comp := map[string]interface{}{
		"type": compTypeAIModel,
		"name": name,
		"boms": []map[string]interface{}{bomMap},
	}
	if modelID := extractMLModelID(doc); modelID != "" {
		comp["modelId"] = modelID
	}
	if ver := extractMLModelVersion(doc); ver != "" {
		comp["version"] = ver
	}
	return comp, nil
}

// buildSPDX3Components fans a multi-subject SPDX 3.0 AI/Dataset document into one
// thin component per subject: an aiModel per ai_AIPackage, a dataset per
// dataset_DatasetPackage, each carrying its normalized spdx-3-ai BOM (whose
// boms[].uniqueId is the subject's stable SPDXID — the reconcile join key).
func buildSPDX3Components(data []byte, doc map[string]interface{}) ([]map[string]interface{}, error) {
	// ParseBom enforces the input-size security boundary and format detection;
	// the multi-subject walk then runs off the already-parsed doc.
	if _, err := bom.ParseBom(data); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX-3 AI/Dataset document: %w", err)
	}

	subjects := bom.ParseSPDX3(doc).Subjects
	if len(subjects) == 0 {
		return nil, fmt.Errorf("SPDX-3 document carries no AI/dataset subjects")
	}

	components := make([]map[string]interface{}, 0, len(subjects))
	for _, subject := range subjects {
		bomMap, err := structToMap(subject.Bom)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize normalized SPDX-3 BOM: %w", err)
		}
		comp := map[string]interface{}{
			"name": subject.Name,
			"boms": []map[string]interface{}{bomMap},
		}
		switch subject.Kind {
		case "aiModel":
			comp["type"] = compTypeAIModel
			if subject.ID != "" {
				comp["modelId"] = subject.ID
			}
		case "dataset":
			comp["type"] = compTypeDataset
			if subject.ID != "" {
				comp["datasetId"] = subject.ID
			}
		}
		components = append(components, comp)
	}
	return components, nil
}

// countComponentKinds tallies aiModel and dataset components for status messages.
func countComponentKinds(components []map[string]interface{}) (models, datasets int) {
	for _, comp := range components {
		switch comp["type"] {
		case compTypeAIModel:
			models++
		case compTypeDataset:
			datasets++
		}
	}
	return models, datasets
}
