/**
 * Shared BOM parser model (ADR-0001 Phase 2 / kirq.2).
 *
 * Re-exports the generated HDF Bill-of-Materials types so the parser and its
 * consumers depend on a single source of truth, and defines the relational
 * graph scaffolding reserved for future CBOM/SaaSBOM normalization. The graph
 * types are present but UNPOPULATED today — they satisfy the card's "supports
 * relational extensions" contract without asserting relationships no current
 * format cleanly provides. Mirrors hdf-converters/shared/go/bom.
 */

import type {
  AIModelBOMExtension,
  BillOfMaterials,
  Checksum,
  DatasetBOMExtension,
  Hyperparameter,
  InputOutput,
  PerformanceMetric,
  SBOMPackage,
} from '@mitre/hdf-schema';

export { DatasetDerivationType, ModelAdaptationType } from '@mitre/hdf-schema';

/**
 * BOM manifest-kind discriminator. The schema allows custom 'x-'-prefixed kinds
 * beyond the reserved set, so the generated `bomType` field is a plain string;
 * the reserved values below are the parser's normalized vocabulary. Mirrors the
 * Go bom package.
 */
export const BOMType = {
  Sbom: 'sbom',
  AIModel: 'ai-model',
  Dataset: 'dataset',
} as const;
export type BOMType = (typeof BOMType)[keyof typeof BOMType];

export type {
  AIModelBOMExtension,
  BillOfMaterials,
  Checksum,
  DatasetBOMExtension,
  Hyperparameter,
  InputOutput,
  PerformanceMetric,
  SBOMPackage,
};

/** Supported source BOM formats the parser can detect and normalize. */
export type BomFormat =
  | 'cyclonedx'
  | 'spdx'
  | 'cyclonedx-ml'
  | 'spdx-3-ai'
  | 'spdx-3-security';

/**
 * A node in the reserved relational-BOM graph (CBOM cryptographic assets,
 * SaaSBOM services, dependency edges). Reserved scaffolding — not populated by
 * the current CycloneDX/SPDX/ML parsers.
 */
export interface RelationalNode {
  /** Stable identifier within the graph (e.g. a bom-ref or SPDXID). */
  id: string;
  /** Node category (e.g. 'component', 'service', 'crypto-algorithm'). */
  kind: string;
  /** Human-readable label. */
  label?: string;
  /** Opaque per-node attributes carried until a normalized shape ships. */
  attributes?: Record<string, unknown>;
}

/**
 * A directed relationship in the reserved relational-BOM graph (e.g.
 * DEPENDS_ON, DESCRIBES). Reserved scaffolding — not populated today.
 */
export interface RelationalEdge {
  /** Source node id. */
  from: string;
  /** Target node id. */
  to: string;
  /** Relationship type (e.g. 'depends-on', 'describes', 'derived-from'). */
  relationship: string;
  /** Opaque per-edge attributes. */
  attributes?: Record<string, unknown>;
}

/**
 * The normalized parser output: a schema-valid BillOfMaterials plus optional
 * relational-graph scaffolding. buildBom() emits the BillOfMaterials core;
 * nodes/edges stay undefined until a relational format is normalized.
 */
export type NormalizedBom = BillOfMaterials & {
  nodes?: RelationalNode[];
  edges?: RelationalEdge[];
};
