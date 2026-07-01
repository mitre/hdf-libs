/**
 * Shared BOM parser public API (ADR-0001 Phase 2 / kirq.2).
 */

export * from './model.js';
export {
  asRecord,
  asString,
  buildBom,
  cleanLicense,
  detectFormat,
  enrichFromPurl,
  parseBom,
  type BuildBomParts,
  type FormatDetection,
  type ParseResult,
} from './normalize.js';
export {
  detectCycloneDX,
  detectCycloneDXML,
  detectSPDX,
} from './fingerprints.js';
export { parseCycloneDX } from './cyclonedx.js';
export { parseSPDX } from './spdx.js';
export { parseMLBOM } from './ml-bom.js';
