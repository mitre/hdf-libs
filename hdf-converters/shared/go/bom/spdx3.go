// SPDX 3.0 AI/Dataset (JSON-LD) -> normalized HDF BillOfMaterials subjects.
//
// SPDX 3.0 is JSON-LD: a top-level { "@context", "@graph" } where "@graph" is an
// array of typed elements. A single document is inherently MULTI-SUBJECT — it
// can carry several ai_AIPackage and dataset_DatasetPackage elements — so this
// parser returns one subject per AI/dataset element (unlike the single-BOM
// ParseSPDX / ParseMLBOM paths). This is completely distinct from SPDX 2.3
// (spdxVersion + packages[]), handled by ParseSPDX.
//
// PARTIAL-FIDELITY: only fields that map cleanly onto the normalized extensions
// are lifted; everything else (energy, autonomy, safety, bias, sensor, size, …)
// is carried opaquely via the BOM document passthrough of the raw element. Two
// conflation traps are deliberately avoided: ai_hyperparameter is training knobs
// (-> Hyperparameters, NEVER ParameterCount) and dataset_datasetSize is
// ambiguous/unlabeled (never -> RecordCount).

package bom

import (
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
)

// SPDX3Subject is a single normalized AI/dataset subject lifted from the
// SPDX-3 @graph.
type SPDX3Subject struct {
	Kind string // "aiModel" | "dataset"
	Name string
	ID   string
	Bom  *NormalizedBom
}

// SPDX3ParseResult carries every AI/dataset subject a document holds.
type SPDX3ParseResult struct {
	Subjects []SPDX3Subject
}

// datasetRelationshipTypes are the SPDX-3 relationship types that link a model
// to a training/evaluation dataset.
var datasetRelationshipTypes = map[string]bool{"trainedOn": true, "testedOn": true}

func graphElements(obj map[string]any) []map[string]any {
	graph, ok := obj["@graph"].([]any)
	if !ok {
		return nil
	}
	out := []map[string]any{}
	for _, el := range graph {
		if r := asRecord(el); r != nil {
			out = append(out, r)
		}
	}
	return out
}

// dictionaryEntries maps SPDX DictionaryEntry[] ({key,value}) to normalized
// name/value pairs.
func dictionaryEntries(value any) [][2]string {
	entries, ok := value.([]any)
	if !ok {
		return nil
	}
	out := [][2]string{}
	for _, entry := range entries {
		e := asRecord(entry)
		if e == nil {
			continue
		}
		name := asString(e["key"])
		if name == "" {
			continue
		}
		val := ""
		if raw, has := e["value"]; has && raw != nil {
			val = stringifyScalar(raw)
		}
		out = append(out, [2]string{name, val})
	}
	return out
}

func toHyperparameters(pairs [][2]string) []Hyperparameter {
	out := make([]Hyperparameter, 0, len(pairs))
	for _, p := range pairs {
		name, val := p[0], p[1]
		out = append(out, Hyperparameter{Name: &name, Value: &val})
	}
	return out
}

func toPerformanceMetrics(pairs [][2]string) []PerformanceMetric {
	out := make([]PerformanceMetric, 0, len(pairs))
	for _, p := range pairs {
		name, val := p[0], p[1]
		out = append(out, PerformanceMetric{Name: &name, Value: &val})
	}
	return out
}

// firstString returns the first non-empty string in a string array, else "".
func firstString(value any) string {
	items, ok := value.([]any)
	if !ok {
		return ""
	}
	for _, item := range items {
		if s := asString(item); s != "" {
			return s
		}
	}
	return ""
}

// joinDistinct joins the distinct non-empty strings of an array with "; ".
func joinDistinct(value any) string {
	items, ok := value.([]any)
	if !ok {
		return ""
	}
	seen := []string{}
	for _, item := range items {
		s := asString(item)
		if s == "" || contains(seen, s) {
			continue
		}
		seen = append(seen, s)
	}
	return strings.Join(seen, "; ")
}

// stringArray collects the non-empty strings of an array.
func stringArray(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range items {
		if s := asString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// datasetRefsFor collects the targets of trainedOn/testedOn relationships whose
// `from` is modelID, resolved to the referenced dataset element's name when
// present in the graph, else the raw id. Distinct, first-seen order.
func datasetRefsFor(modelID string, relationships []map[string]any, datasetNameByID map[string]string) []string {
	out := []string{}
	for _, rel := range relationships {
		if asString(rel["from"]) != modelID {
			continue
		}
		if !datasetRelationshipTypes[asString(rel["relationshipType"])] {
			continue
		}
		targets, ok := rel["to"].([]any)
		if !ok {
			if single := rel["to"]; single != nil {
				targets = []any{single}
			}
		}
		for _, target := range targets {
			targetID := asString(target)
			if targetID == "" {
				continue
			}
			ref := targetID
			if name, found := datasetNameByID[targetID]; found {
				ref = name
			}
			if !contains(out, ref) {
				out = append(out, ref)
			}
		}
	}
	return out
}

func buildSPDX3ModelExtension(element map[string]any, relationships []map[string]any, datasetNameByID map[string]string) *AIModelBOMExtension {
	model := &AIModelBOMExtension{}

	if hp := dictionaryEntries(element["ai_hyperparameter"]); len(hp) > 0 {
		model.Hyperparameters = toHyperparameters(hp)
	}
	if metrics := dictionaryEntries(element["ai_metric"]); len(metrics) > 0 {
		model.PerformanceMetrics = toPerformanceMetrics(metrics)
	}
	if task := firstString(element["ai_domain"]); task != "" {
		model.Task = strPtr(task)
	}
	if architecture := joinDistinct(element["ai_typeOfModel"]); architecture != "" {
		model.ModelArchitecture = strPtr(architecture)
	}
	if intendedUse := asString(element["ai_informationAboutApplication"]); intendedUse != "" {
		model.IntendedUse = strPtr(intendedUse)
	}
	if refs := datasetRefsFor(asString(element["spdxId"]), relationships, datasetNameByID); len(refs) > 0 {
		model.DatasetRefs = refs
	}

	return model
}

func buildSPDX3DatasetExtension(element map[string]any) *DatasetBOMExtension {
	dataset := &DatasetBOMExtension{}

	if values := stringArray(element["dataset_datasetType"]); len(values) > 0 {
		dataset.Modality = &Modality{StringArray: values}
	}
	if dataClassification := asString(element["dataset_confidentialityLevel"]); dataClassification != "" {
		dataset.DataClassification = strPtr(dataClassification)
	}
	if intendedUse := asString(element["dataset_intendedUse"]); intendedUse != "" {
		dataset.IntendedUse = strPtr(intendedUse)
	}
	if provenance := asString(element["dataset_dataCollectionProcess"]); provenance != "" {
		dataset.Provenance = strPtr(provenance)
	}

	return dataset
}

// ParseSPDX3 parses an SPDX-3 JSON-LD document into its AI/dataset subjects. It
// emits one aiModel subject per ai_AIPackage and one dataset subject per
// dataset_DatasetPackage, in graph order.
func ParseSPDX3(obj map[string]any) *SPDX3ParseResult {
	elements := graphElements(obj)

	relationships := []map[string]any{}
	datasetNameByID := map[string]string{}
	for _, el := range elements {
		switch el["type"] {
		case "Relationship":
			relationships = append(relationships, el)
		case "dataset_DatasetPackage":
			if id, name := asString(el["spdxId"]), asString(el["name"]); id != "" && name != "" {
				datasetNameByID[id] = name
			}
		}
	}

	subjects := []SPDX3Subject{}
	for _, element := range elements {
		switch element["type"] {
		case "ai_AIPackage":
			model := buildSPDX3ModelExtension(element, relationships, datasetNameByID)
			subjects = append(subjects, SPDX3Subject{
				Kind: "aiModel",
				Name: asString(element["name"]),
				ID:   asString(element["spdxId"]),
				Bom: normalized(BuildBom(BuildBomParts{
					BOMType:  BOMTypeAIModel,
					Format:   FormatSPDX3AI,
					Model:    model,
					Document: element,
					UniqueID: strPtr(asString(element["spdxId"])),
				})),
			})
		case "dataset_DatasetPackage":
			dataset := buildSPDX3DatasetExtension(element)
			subjects = append(subjects, SPDX3Subject{
				Kind: "dataset",
				Name: asString(element["name"]),
				ID:   asString(element["spdxId"]),
				Bom: normalized(BuildBom(BuildBomParts{
					BOMType:  BOMTypeDataset,
					Format:   FormatSPDX3AI,
					Dataset:  dataset,
					Document: element,
					UniqueID: strPtr(asString(element["spdxId"])),
				})),
			})
		}
	}

	return &SPDX3ParseResult{Subjects: shared.LimitSliceWithWarning(subjects, maxPackages, "subject")}
}
