/**
 * Shared BOM normalization: parseBom / buildBom / detectFormat re-dispatch and
 * the cross-format helpers (object guards, license cleaning, purl handling).
 * Format-specific extraction lives in cyclonedx.ts / spdx.ts / ml-bom.ts.
 */

import { parseJSON, parsePurl } from '@mitre/hdf-utilities';
import { validateInputSize } from '../converterutil.js';
import {
  BOMType,
  type AIModelBOMExtension,
  type BillOfMaterials,
  type Checksum,
  type DatasetBOMExtension,
  type NormalizedBom,
  type SBOMPackage,
} from './model.js';
import { detectFormat } from './fingerprints.js';
import { parseCycloneDX } from './cyclonedx.js';
import { parseSPDX } from './spdx.js';
import { parseSPDX3 } from './spdx3.js';
import { parseMLBOM } from './ml-bom.js';

export { detectFormat, type FormatDetection } from './fingerprints.js';

const CONVERTER = 'bom-parser';

/** SPDX sentinels that mean "no license", filtered out of normalized output. */
const SPDX_NULL_LICENSES = new Set(['noassertion', 'none']);

export interface ParseResult {
  format: string;
  normalized: NormalizedBom;
}

/** Parts accepted by buildBom. Only the extension matching bomType is kept. */
export interface BuildBomParts {
  bomType: BOMType;
  format: string;
  packages?: SBOMPackage[];
  model?: AIModelBOMExtension;
  dataset?: DatasetBOMExtension;
  ref?: string;
  document?: Record<string, unknown>;
  uniqueId?: string;
  hashes?: Checksum[];
  license?: string | null;
}

/** Narrow an unknown value to a plain object (not array, not null). */
export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Narrow an unknown value to a non-empty string. */
export function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Render a heterogeneous scalar BOM value (metric value, SPDX DictionaryEntry
 * value) to a string. This is the REFERENCE the Go side matches byte-for-byte
 * (see stringifyScalar / jsNumberToString in normalize.go): JS String() gives
 * numbers their shortest round-tripping form, and Go reimplements that exact
 * formatting. Callers must guard null/undefined before calling.
 */
export function stringifyScalar(value: unknown): string {
  return String(value);
}

/** Return an SPDX license string unless it is a NOASSERTION/NONE sentinel. */
export function cleanLicense(value: unknown): string | undefined {
  const s = asString(value);
  if (!s) return undefined;
  return SPDX_NULL_LICENSES.has(s.trim().toLowerCase()) ? undefined : s;
}

/**
 * Fill a package's missing name/version from its purl when parseable. Never
 * overwrites values the source BOM already provided (e.g. an SPDX versionInfo
 * is authoritative over a purl whose @segment is a git commit).
 */
export function enrichFromPurl(pkg: SBOMPackage): void {
  if (!pkg.purl) return;
  const parsed = parsePurl(pkg.purl);
  if (!parsed) return;
  if (!pkg.version && parsed.version) pkg.version = parsed.version;
  if (!pkg.name && parsed.name) pkg.name = parsed.name;
}

/**
 * Assemble a schema-valid BillOfMaterials from normalized parts, enforcing the
 * three-tier discipline: the packages/model/dataset extension is kept only when
 * it matches bomType; a mismatched extension is silently dropped (the schema
 * forbids it, so carrying it would produce invalid output).
 */
export function buildBom(parts: BuildBomParts): BillOfMaterials {
  const bom: BillOfMaterials = { bomType: parts.bomType, format: parts.format };

  if (parts.ref !== undefined) bom.ref = parts.ref;
  if (parts.document !== undefined) bom.document = parts.document;
  if (parts.uniqueId !== undefined) bom.uniqueId = parts.uniqueId;
  if (parts.hashes !== undefined && parts.hashes.length > 0) bom.hashes = parts.hashes;
  if (parts.license !== undefined) bom.license = parts.license;

  if (parts.bomType === BOMType.Sbom && parts.packages !== undefined) {
    bom.packages = parts.packages;
  }
  if (parts.bomType === BOMType.AIModel && parts.model !== undefined) {
    bom.model = parts.model;
  }
  if (parts.bomType === BOMType.Dataset && parts.dataset !== undefined) {
    bom.dataset = parts.dataset;
  }

  return bom;
}

/**
 * Detect and parse a BOM document into normalized form. Validates input size
 * FIRST (security boundary), then dispatches on the detected format. Throws on
 * oversized or undetectable input.
 */
export function parseBom(input: string): ParseResult {
  validateInputSize(input, CONVERTER);
  const obj = parseJSON<unknown>(input);
  const detected = detectFormat(obj);
  if (!detected) {
    throw new Error(
      'bom-parser: could not detect a supported BOM format (expected CycloneDX or SPDX JSON)',
    );
  }
  const record = asRecord(obj) ?? {};
  switch (detected.format) {
    case 'cyclonedx-ml':
      return { format: detected.format, normalized: parseMLBOM(record) };
    case 'cyclonedx':
      return { format: detected.format, normalized: parseCycloneDX(record) };
    case 'spdx':
      return { format: detected.format, normalized: parseSPDX(record) };
    case 'spdx-3-ai': {
      // SPDX-3 is multi-subject; parseBom's single-BOM contract returns the
      // first subject's BOM. The full multi-subject consumer is parseSPDX3.
      const [first] = parseSPDX3(record).subjects;
      if (!first) {
        throw new Error('bom-parser: SPDX-3 document carries no AI/dataset subjects');
      }
      return { format: detected.format, normalized: first.bom };
    }
  }
}
