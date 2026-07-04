/**
 * SPDX 3.0 AI/Dataset (JSON-LD) -> normalized HDF BillOfMaterials subjects.
 *
 * SPDX 3.0 is JSON-LD: a top-level { "@context", "@graph" } where "@graph" is an
 * array of typed elements. A single document is inherently MULTI-SUBJECT — it
 * can carry several ai_AIPackage and dataset_DatasetPackage elements — so this
 * parser returns one subject per AI/dataset element (unlike the single-BOM
 * parseSPDX / parseMLBOM paths). This is completely distinct from SPDX 2.3
 * (spdxVersion + packages[]), handled by parseSPDX.
 *
 * PARTIAL-FIDELITY: only fields that map cleanly onto the normalized extensions
 * are lifted; everything else (energy, autonomy, safety, bias, sensor, size, …)
 * is carried opaquely via the BOM `document` passthrough of the raw element.
 * Two conflation traps are deliberately avoided: ai_hyperparameter is training
 * knobs (-> hyperparameters, NEVER parameterCount) and dataset_datasetSize is
 * ambiguous/unlabeled (never -> recordCount).
 */

import {
  BOMType,
  type AIModelBOMExtension,
  type DatasetBOMExtension,
  type Hyperparameter,
  type NormalizedBom,
  type PerformanceMetric,
} from './model.js';
import { asRecord, asString, buildBom, stringifyScalar } from './normalize.js';

/** A single normalized AI/dataset subject lifted from the SPDX-3 @graph. */
export interface SPDX3Subject {
  kind: 'aiModel' | 'dataset';
  name: string;
  id: string;
  bom: NormalizedBom;
}

/** Result of parsing an SPDX-3 document: every AI/dataset subject it carries. */
export interface SPDX3ParseResult {
  subjects: SPDX3Subject[];
}

/** SPDX-3 relationship types that link a model to a training/eval dataset. */
const DATASET_RELATIONSHIP_TYPES = new Set(['trainedOn', 'testedOn']);

function graphElements(obj: Record<string, unknown>): Record<string, unknown>[] {
  const graph = obj['@graph'];
  if (!Array.isArray(graph)) return [];
  const out: Record<string, unknown>[] = [];
  for (const el of graph) {
    const r = asRecord(el);
    if (r) out.push(r);
  }
  return out;
}

/** Map SPDX DictionaryEntry[] ({key,value}) to normalized {name,value} pairs. */
function dictionaryEntries(value: unknown): Array<{ name: string; value: string }> {
  if (!Array.isArray(value)) return [];
  const out: Array<{ name: string; value: string }> = [];
  for (const entry of value) {
    const e = asRecord(entry);
    if (!e) continue;
    const name = asString(e.key);
    if (name === undefined) continue;
    const value = e.value !== undefined && e.value !== null ? stringifyScalar(e.value) : '';
    out.push({ name, value });
  }
  return out;
}

/** First element of a non-empty string array, else undefined. */
function firstString(value: unknown): string | undefined {
  if (!Array.isArray(value)) return undefined;
  for (const item of value) {
    const s = asString(item);
    if (s !== undefined) return s;
  }
  return undefined;
}

/** Distinct non-empty strings of an array, joined with "; ". */
function joinDistinct(value: unknown): string | undefined {
  if (!Array.isArray(value)) return undefined;
  const seen: string[] = [];
  for (const item of value) {
    const s = asString(item);
    if (s !== undefined && !seen.includes(s)) seen.push(s);
  }
  return seen.length > 0 ? seen.join('; ') : undefined;
}

/**
 * Dataset references for a model: targets of trainedOn/testedOn relationships
 * whose `from` is this model. Each target is resolved to the referenced
 * dataset element's name when present in the graph, else the raw id. Distinct,
 * first-seen order.
 */
function datasetRefsFor(
  modelId: string,
  relationships: Record<string, unknown>[],
  datasetNameById: Map<string, string>,
): string[] {
  const out: string[] = [];
  for (const rel of relationships) {
    if (asString(rel.from) !== modelId) continue;
    if (!DATASET_RELATIONSHIP_TYPES.has(asString(rel.relationshipType) ?? '')) continue;
    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    for (const target of targets) {
      const targetId = asString(target);
      if (targetId === undefined) continue;
      const ref = datasetNameById.get(targetId) ?? targetId;
      if (!out.includes(ref)) out.push(ref);
    }
  }
  return out;
}

function buildModelExtension(
  element: Record<string, unknown>,
  relationships: Record<string, unknown>[],
  datasetNameById: Map<string, string>,
): AIModelBOMExtension {
  const model: AIModelBOMExtension = {};

  const hyperparameters: Hyperparameter[] = dictionaryEntries(element.ai_hyperparameter);
  if (hyperparameters.length > 0) model.hyperparameters = hyperparameters;

  const performanceMetrics: PerformanceMetric[] = dictionaryEntries(element.ai_metric);
  if (performanceMetrics.length > 0) model.performanceMetrics = performanceMetrics;

  const task = firstString(element.ai_domain);
  if (task !== undefined) model.task = task;

  const architecture = joinDistinct(element.ai_typeOfModel);
  if (architecture !== undefined) model.modelArchitecture = architecture;

  const intendedUse = asString(element.ai_informationAboutApplication);
  if (intendedUse !== undefined) model.intendedUse = intendedUse;

  const datasetRefs = datasetRefsFor(asString(element.spdxId) ?? '', relationships, datasetNameById);
  if (datasetRefs.length > 0) model.datasetRefs = datasetRefs;

  return model;
}

function buildDatasetExtension(element: Record<string, unknown>): DatasetBOMExtension {
  const dataset: DatasetBOMExtension = {};

  const modality = element.dataset_datasetType;
  if (Array.isArray(modality)) {
    const values = modality.map(asString).filter((s): s is string => s !== undefined);
    if (values.length > 0) dataset.modality = values;
  }

  const dataClassification = asString(element.dataset_confidentialityLevel);
  if (dataClassification !== undefined) dataset.dataClassification = dataClassification;

  const intendedUse = asString(element.dataset_intendedUse);
  if (intendedUse !== undefined) dataset.intendedUse = intendedUse;

  const provenance = asString(element.dataset_dataCollectionProcess);
  if (provenance !== undefined) dataset.provenance = provenance;

  return dataset;
}

/**
 * Parse an SPDX-3 JSON-LD document into its AI/dataset subjects. Emits one
 * aiModel subject per ai_AIPackage and one dataset subject per
 * dataset_DatasetPackage, in graph order.
 */
export function parseSPDX3(obj: Record<string, unknown>): SPDX3ParseResult {
  const elements = graphElements(obj);
  const relationships = elements.filter(el => el.type === 'Relationship');

  const datasetNameById = new Map<string, string>();
  for (const el of elements) {
    if (el.type !== 'dataset_DatasetPackage') continue;
    const id = asString(el.spdxId);
    const name = asString(el.name);
    if (id !== undefined && name !== undefined) datasetNameById.set(id, name);
  }

  const subjects: SPDX3Subject[] = [];
  for (const element of elements) {
    if (element.type === 'ai_AIPackage') {
      const model = buildModelExtension(element, relationships, datasetNameById);
      subjects.push({
        kind: 'aiModel',
        name: asString(element.name) ?? '',
        id: asString(element.spdxId) ?? '',
        bom: buildBom({
          bomType: BOMType.AIModel,
          format: 'spdx-3-ai',
          model,
          document: element,
          uniqueId: asString(element.spdxId),
        }),
      });
    } else if (element.type === 'dataset_DatasetPackage') {
      const dataset = buildDatasetExtension(element);
      subjects.push({
        kind: 'dataset',
        name: asString(element.name) ?? '',
        id: asString(element.spdxId) ?? '',
        bom: buildBom({
          bomType: BOMType.Dataset,
          format: 'spdx-3-ai',
          dataset,
          document: element,
          uniqueId: asString(element.spdxId),
        }),
      });
    }
  }

  return { subjects };
}
