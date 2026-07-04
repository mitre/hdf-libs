// CycloneDX ML-BOM -> normalized HDF ai-model BillOfMaterials.
//
// PARTIAL-FIDELITY: only modelCard fields that map cleanly onto the normalized
// AI_Model_Extension are lifted (modelArchitecture, datasetRefs, intendedUse,
// learningApproach, task, performanceMetrics, inputOutput.dataTypes).
// parameterCount, serializationFormat, hyperparameters, and the rest of
// inputOutput have NO native CycloneDX ML source, so they are left nil — never
// fabricated. The raw machine-learning-model component is carried verbatim in
// the BOM document passthrough so nothing is lost, satisfying the
// "drop-or-passthrough, never invent" rule.

package bom

import (
	"strings"
)

func findModelComponent(obj map[string]any) map[string]any {
	components, _ := obj["components"].([]any)
	for _, component := range components {
		c := asRecord(component)
		if c != nil && c["type"] == "machine-learning-model" {
			return c
		}
	}
	return nil
}

// extractDatasetRefs lifts references to training/evaluation datasets. Only
// ref-shaped entries (a bare ref string, or an object with a `ref`) are lifted;
// inline dataset descriptors without a reference are left for a future
// dataset-normalization pass rather than being synthesized into a ref.
func extractDatasetRefs(datasets any) []string {
	entries, ok := datasets.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, dataset := range entries {
		if s, isStr := dataset.(string); isStr {
			if len(s) > 0 {
				out = append(out, s)
			}
			continue
		}
		if ref := asString(asRecord(dataset)["ref"]); ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

// extractIntendedUse builds an intended-use statement from
// modelCard.considerations.useCases, if present.
func extractIntendedUse(considerations any) string {
	c := asRecord(considerations)
	if c == nil {
		return ""
	}
	useCases, ok := c["useCases"].([]any)
	if !ok {
		return ""
	}
	parts := []string{}
	for _, uc := range useCases {
		if s := asString(uc); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

// extractPerformanceMetrics lifts reported evaluation metrics from
// modelCard.quantitativeAnalysis. Each native metric's `type` becomes the
// normalized `name` and its `value` is carried as a string (metrics are
// heterogeneous). An entry contributes only when it has a name or value; native
// slice/confidenceInterval detail stays in the document passthrough.
func extractPerformanceMetrics(quantitativeAnalysis any) []PerformanceMetric {
	qa := asRecord(quantitativeAnalysis)
	if qa == nil {
		return nil
	}
	entries, ok := qa["performanceMetrics"].([]any)
	if !ok {
		return nil
	}
	out := []PerformanceMetric{}
	for _, entry := range entries {
		e := asRecord(entry)
		if e == nil {
			continue
		}
		name := asString(e["type"])
		rawValue, hasValue := e["value"]
		valueSet := hasValue && rawValue != nil
		if name == "" && !valueSet {
			continue
		}
		metric := PerformanceMetric{}
		if name != "" {
			metric.Name = strPtr(name)
		}
		if valueSet {
			value := stringifyScalar(rawValue)
			metric.Value = &value
		}
		out = append(out, metric)
	}
	return out
}

// extractIODataTypes collects the distinct `format` strings across
// modelParameters.inputs[] and outputs[], preserving first-seen order.
func extractIODataTypes(parameters map[string]any) []string {
	out := []string{}
	for _, key := range []string{"inputs", "outputs"} {
		entries, ok := parameters[key].([]any)
		if !ok {
			continue
		}
		for _, entry := range entries {
			format := asString(asRecord(entry)["format"])
			if format == "" {
				continue
			}
			seen := false
			for _, existing := range out {
				if existing == format {
					seen = true
					break
				}
			}
			if !seen {
				out = append(out, format)
			}
		}
	}
	return out
}

func buildModelExtension(modelComponent map[string]any) *AIModelBOMExtension {
	model := &AIModelBOMExtension{}
	modelCard := asRecord(modelComponent["modelCard"])
	if modelCard == nil {
		return model
	}

	if parameters := asRecord(modelCard["modelParameters"]); parameters != nil {
		architecture := asString(parameters["modelArchitecture"])
		if architecture == "" {
			architecture = asString(parameters["architectureFamily"])
		}
		if architecture != "" {
			model.ModelArchitecture = strPtr(architecture)
		}
		if datasetRefs := extractDatasetRefs(parameters["datasets"]); len(datasetRefs) > 0 {
			model.DatasetRefs = datasetRefs
		}
		if learningApproach := asString(asRecord(parameters["approach"])["type"]); learningApproach != "" {
			model.LearningApproach = strPtr(learningApproach)
		}
		if task := asString(parameters["task"]); task != "" {
			model.Task = strPtr(task)
		}
		if dataTypes := extractIODataTypes(parameters); len(dataTypes) > 0 {
			model.InputOutput = &InputOutput{DataTypes: dataTypes}
		}
	}

	if metrics := extractPerformanceMetrics(modelCard["quantitativeAnalysis"]); len(metrics) > 0 {
		model.PerformanceMetrics = metrics
	}

	if intendedUse := extractIntendedUse(modelCard["considerations"]); intendedUse != "" {
		model.IntendedUse = strPtr(intendedUse)
	}

	return model
}

// ParseMLBOM normalizes a CycloneDX ML-BOM object into an ai-model
// BillOfMaterials.
func ParseMLBOM(obj map[string]any) *NormalizedBom {
	modelComponent := findModelComponent(obj)
	model := &AIModelBOMExtension{}
	if modelComponent != nil {
		model = buildModelExtension(modelComponent)
	}

	return normalized(BuildBom(BuildBomParts{
		BOMType:  BOMTypeAIModel,
		Format:   FormatCycloneDXML,
		Model:    model,
		Document: modelComponent,
		UniqueID: strPtr(asString(obj["serialNumber"])),
	}))
}
