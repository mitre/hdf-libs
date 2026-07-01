/**
 * CycloneDX ML-BOM -> normalized HDF ai-model BillOfMaterials.
 *
 * PARTIAL-FIDELITY: only modelCard fields that map cleanly onto the normalized
 * AI_Model_Extension are lifted (modelArchitecture, datasetRefs, intendedUse).
 * parameterCount and serializationFormat have NO native CycloneDX ML source, so
 * they are left undefined — never fabricated. The raw machine-learning-model
 * component is carried verbatim in the BOM `document` passthrough so nothing is
 * lost, satisfying the "drop-or-passthrough, never invent" rule.
 */

import {
  BOMType,
  type AIModelBOMExtension,
  type NormalizedBom,
} from './model.js';
import {
  asRecord,
  asString,
  buildBom,
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
  }

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
