/**
 * CycloneDX ML-BOM -> normalized HDF ai-model BillOfMaterials.
 *
 * PARTIAL-FIDELITY: only modelCard fields that map cleanly onto the normalized
 * AI_Model_Extension are lifted (modelArchitecture, datasetRefs, intendedUse,
 * learningApproach, task, performanceMetrics, inputOutput.dataTypes).
 * parameterCount, serializationFormat, hyperparameters, and the rest of
 * inputOutput have NO native CycloneDX ML source, so they are left undefined —
 * never fabricated. The raw machine-learning-model component is carried verbatim
 * in the BOM `document` passthrough so nothing is lost, satisfying the
 * "drop-or-passthrough, never invent" rule.
 */

import {
  BOMType,
  type AIModelBOMExtension,
  type InputOutput,
  type NormalizedBom,
  type PerformanceMetric,
} from './model.js';
import {
  asRecord,
  asString,
  buildBom,
  stringifyScalar,
} from './normalize.js';

function findModelComponent(obj: Record<string, unknown>): Record<string, unknown> | undefined {
  const components = Array.isArray(obj.components) ? obj.components : [];
  for (const component of components) {
    const c = asRecord(component);
    if (c?.type === 'machine-learning-model') return c;
  }
  return undefined;
}

/**
 * References to training/evaluation datasets. Only ref-shaped entries (a bare
 * ref string, or an object with a `ref`) are lifted; inline dataset descriptors
 * without a reference are left for a future dataset-normalization pass rather
 * than being synthesized into a ref.
 */
function extractDatasetRefs(datasets: unknown): string[] {
  if (!Array.isArray(datasets)) return [];
  const out: string[] = [];
  for (const dataset of datasets) {
    if (typeof dataset === 'string') {
      if (dataset.length > 0) out.push(dataset);
      continue;
    }
    const ref = asString(asRecord(dataset)?.ref);
    if (ref) out.push(ref);
  }
  return out;
}

/** Intended-use statement from modelCard.considerations.useCases, if present. */
function extractIntendedUse(considerations: unknown): string | undefined {
  const c = asRecord(considerations);
  if (!c || !Array.isArray(c.useCases)) return undefined;
  const parts = c.useCases
    .map(asString)
    .filter((s): s is string => s !== undefined);
  return parts.length > 0 ? parts.join('; ') : undefined;
}

/**
 * Reported evaluation metrics from modelCard.quantitativeAnalysis. Each native
 * metric's `type` becomes the normalized `name` and its `value` is carried as a
 * string (metrics are heterogeneous). An entry contributes only when it has a
 * name or value; native slice/confidenceInterval are left in the `document`.
 */
function extractPerformanceMetrics(quantitativeAnalysis: unknown): PerformanceMetric[] {
  const qa = asRecord(quantitativeAnalysis);
  if (!qa || !Array.isArray(qa.performanceMetrics)) return [];
  const out: PerformanceMetric[] = [];
  for (const entry of qa.performanceMetrics) {
    const e = asRecord(entry);
    if (!e) continue;
    const name = asString(e.type);
    const value = e.value !== undefined && e.value !== null ? stringifyScalar(e.value) : undefined;
    if (name === undefined && value === undefined) continue;
    const metric: PerformanceMetric = {};
    if (name !== undefined) metric.name = name;
    if (value !== undefined) metric.value = value;
    out.push(metric);
  }
  return out;
}

/** Distinct `format` strings across modelParameters.inputs[] and outputs[]. */
function extractIODataTypes(parameters: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ['inputs', 'outputs']) {
    const entries = parameters[key];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const format = asString(asRecord(entry)?.format);
      if (format && !out.includes(format)) out.push(format);
    }
  }
  return out;
}

function buildModelExtension(modelComponent: Record<string, unknown>): AIModelBOMExtension {
  const model: AIModelBOMExtension = {};
  const modelCard = asRecord(modelComponent.modelCard);
  if (!modelCard) return model;

  const parameters = asRecord(modelCard.modelParameters);
  if (parameters) {
    const architecture =
      asString(parameters.modelArchitecture) ?? asString(parameters.architectureFamily);
    if (architecture) model.modelArchitecture = architecture;
    const datasetRefs = extractDatasetRefs(parameters.datasets);
    if (datasetRefs.length > 0) model.datasetRefs = datasetRefs;

    const learningApproach = asString(asRecord(parameters.approach)?.type);
    if (learningApproach) model.learningApproach = learningApproach;

    const task = asString(parameters.task);
    if (task) model.task = task;

    const dataTypes = extractIODataTypes(parameters);
    if (dataTypes.length > 0) {
      const inputOutput: InputOutput = { dataTypes };
      model.inputOutput = inputOutput;
    }
  }

  const performanceMetrics = extractPerformanceMetrics(modelCard.quantitativeAnalysis);
  if (performanceMetrics.length > 0) model.performanceMetrics = performanceMetrics;

  const intendedUse = extractIntendedUse(modelCard.considerations);
  if (intendedUse) model.intendedUse = intendedUse;

  return model;
}

export function parseMLBOM(obj: Record<string, unknown>): NormalizedBom {
  const modelComponent = findModelComponent(obj);
  const model = modelComponent ? buildModelExtension(modelComponent) : {};

  return buildBom({
    bomType: BOMType.AIModel,
    format: 'cyclonedx-ml',
    model,
    document: modelComponent,
    uniqueId: asString(obj.serialNumber),
  });
}
