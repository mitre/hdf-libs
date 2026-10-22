/**
 * BOM format fingerprints + detectFormat dispatcher.
 *
 * Self-contained structural detectors for the three supported BOM formats.
 * Detection precedence: an ML-BOM is a CycloneDX document with a
 * machine-learning-model component, so the ML detector must win over the plain
 * CycloneDX detector.
 *
 * ASYMMETRY NOTE (parity with Go): the Go peer exposes the same detectFormat
 * logic but has NO fingerprint registry — CLI auto-detect wiring is Phase 3 in
 * both languages. These BOM detectors are deliberately NOT registered in the
 * shared ConverterFingerprint registry (shared/typescript/registry.ts): that
 * registry drives full-document CLI auto-detection, and a BOM detector
 * returning 1.0 for a CycloneDX file would tie with the existing
 * cyclonedx-to-hdf converter fingerprint, making detectConverter refuse to
 * guess (ambiguous-tie rule) and regressing every CycloneDX input. BOM parsing
 * is a sub-document concern with no CLI converter until Phase 3.
 */

import type { BomFormat } from './model.js';

export interface FormatDetection {
  format: BomFormat;
  /** Detection confidence in the range 0..1. */
  confidence: number;
}

function record(input: unknown): Record<string, unknown> | undefined {
  return typeof input === 'object' && input !== null && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : undefined;
}

/**
 * Whether a bomFormat value names CycloneDX, ASCII case-insensitively.
 *
 * The spec requires the exact spelling, but a document this package declines
 * falls through to HDF document detection, which reaches `components` after
 * five more specific keys — so a CycloneDX SBOM would be filed as an HDF
 * system, a worse answer than "not a BOM". Case only: a value with surrounding
 * whitespace is a different value.
 */
function isCycloneDXFormat(v: unknown): boolean {
  return typeof v === 'string' && asciiLower(v) === 'cyclonedx';
}

/** CycloneDX: bomFormat naming CycloneDX, any casing. Returns 0..1 confidence. */
export function detectCycloneDX(input: unknown): number {
  const obj = record(input);
  return isCycloneDXFormat(obj?.bomFormat) ? 1 : 0;
}

/**
 * CycloneDX ML-BOM: a CycloneDX document with at least one
 * machine-learning-model component. Strictly more specific than plain
 * CycloneDX.
 */
export function detectCycloneDXML(input: unknown): number {
  const obj = record(input);
  // obj is narrowed explicitly: the old inline compare did it implicitly, and a
  // predicate call cannot.
  if (!obj || !isCycloneDXFormat(obj.bomFormat)) return 0;
  const components = obj.components;
  if (!Array.isArray(components)) return 0;
  const hasModel = components.some(
    c => record(c)?.type === 'machine-learning-model',
  );
  return hasModel ? 1 : 0;
}

/** SPDX: a non-empty spdxVersion string is present. Returns 0..1 confidence. */
export function detectSPDX(input: unknown): number {
  const obj = record(input);
  return typeof obj?.spdxVersion === 'string' && obj.spdxVersion.length > 0 ? 1 : 0;
}

/**
 * SPDX 3.0 AI/Dataset (JSON-LD): a document with an `@context` and an `@graph`
 * array carrying at least one ai_AIPackage or dataset_DatasetPackage element.
 * Structurally disjoint from the SPDX 2.3 detector (which keys on spdxVersion),
 * so the two never conflict.
 */
export function detectSPDX3(input: unknown): number {
  const obj = record(input);
  if (!obj || obj['@context'] === undefined) return 0;
  const graph = obj['@graph'];
  if (!Array.isArray(graph)) return 0;
  const hasAISubject = graph.some(el => {
    const type = record(el)?.type;
    return type === 'ai_AIPackage' || type === 'dataset_DatasetPackage';
  });
  return hasAISubject ? 1 : 0;
}

/**
 * SPDX 3.0 security / VEX (JSON-LD): a document with an `@context` and an
 * `@graph` array carrying at least one security_Vex*VulnAssessmentRelationship
 * element (the four VEX assessment subtypes: Affected, NotAffected, Fixed,
 * UnderInvestigation). Structurally disjoint from the SPDX 2.3 detector (which
 * keys on spdxVersion) and from the SPDX 3.0 AI/Dataset detector (which keys on
 * ai_AIPackage / dataset_DatasetPackage), so none of the three conflict.
 */
export function detectSPDX3Security(input: unknown): number {
  const obj = record(input);
  if (!obj || obj['@context'] === undefined) return 0;
  const graph = obj['@graph'];
  if (!Array.isArray(graph)) return 0;
  const hasVexAssessment = graph.some(el => isVexAssessmentType(record(el)?.type));
  return hasVexAssessment ? 1 : 0;
}

/** True when an SPDX-3 element type is one of the four VEX assessment subtypes. */
function isVexAssessmentType(type: unknown): boolean {
  return (
    typeof type === 'string' &&
    type.startsWith('security_Vex') &&
    type.endsWith('VulnAssessmentRelationship')
  );
}

const MAX_CONTEXT_DEPTH = 32;

/**
 * Whether a JSON-LD @context names an SPDX 3 vocabulary.
 *
 * The value may be a string, an array, or an object whose values are either;
 * an SPDX document adding an extension vocabulary uses the array form, so a
 * string-only check declines a conformant SBOM.
 *
 * Do NOT reach for `new URL` or `toLowerCase` here. Both were tried and both
 * made the two languages disagree: the WHATWG parser throws on "//host/path"
 * where Go's net/url reads an authority, and Go's EqualFold folds U+017F
 * against 's' where toLowerCase does not. Every clause below is plain string
 * work, pinned by the shared vector table.
 */
function isSPDX3Context(v: unknown, depth = 0): boolean {
  if (depth > MAX_CONTEXT_DEPTH) return false;
  if (typeof v === 'string') return isSPDX3ContextURL(v);
  if (Array.isArray(v)) return v.some(el => isSPDX3Context(el, depth + 1));
  if (typeof v === 'object' && v !== null) {
    return Object.values(v as Record<string, unknown>).some(el => isSPDX3Context(el, depth + 1));
  }
  return false;
}

/**
 * Lowercases A-Z and nothing else. `String.prototype.toLowerCase` applies Unicode
 * lowercase mapping and Go's `strings.EqualFold` applies Unicode simple case
 * folding — which matches U+017F LATIN SMALL LETTER LONG S against 's' where
 * toLowerCase does not. Two stdlib case operations that look equivalent are not,
 * so neither is used: RFC 3986 section 6.2.2.1 specifies ASCII case
 * normalization for the scheme and host, which is what this does.
 */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + 32));
}

function isSPDX3ContextURL(s: string): boolean {
  // These exact characters, not a category: see the doc comment above for what is
  // and is not covered, and the table for which of them a row isolates.
  if (/[ \t\r\n\\%]/.test(s) || s.includes('..')) return false;
  let rest: string | undefined;
  for (const scheme of ['https://', 'http://']) {
    if (asciiLower(s.slice(0, scheme.length)) === scheme) {
      rest = s.slice(scheme.length);
      break;
    }
  }
  if (rest === undefined) return false;
  const slash = rest.indexOf('/');
  if (slash < 0) return false;
  let host = rest.slice(0, slash);
  const colon = host.indexOf(':');
  if (colon >= 0) host = host.slice(0, colon);
  if (asciiLower(host) !== 'spdx.org') return false;
  const path = rest.slice(slash);
  if (!path.startsWith('/rdf/')) return false;
  const version = path.slice('/rdf/'.length);
  return version.startsWith('3.') || version === '3';
}

/**
 * Whether input is a bill of materials at all. This is a WIDER question than
 * detectFormat, which answers which format parseBom can normalize — and of the
 * SPDX-3 profiles it normalizes the AI/dataset one only, so a plain SPDX 3
 * software-profile SBOM is a real BOM that detectFormat declines.
 *
 * A caller that RECORDS A REFERENCE and never parses needs this one. Asking the
 * narrower question left such an SBOM classified as foreign.
 */
export function isBOMDocument(input: unknown): boolean {
  if (detectFormat(input) !== undefined) return true;
  const obj = record(input);
  return obj !== undefined && isSPDX3Context(obj['@context']);
}

/**
 * Detect the BOM format of a parsed JSON object. ML wins over plain CycloneDX
 * by precedence; returns undefined when no supported format matches.
 */
export function detectFormat(input: unknown): FormatDetection | undefined {
  const ml = detectCycloneDXML(input);
  if (ml > 0) return { format: 'cyclonedx-ml', confidence: ml };
  const cdx = detectCycloneDX(input);
  if (cdx > 0) return { format: 'cyclonedx', confidence: cdx };
  const spdx3 = detectSPDX3(input);
  if (spdx3 > 0) return { format: 'spdx-3-ai', confidence: spdx3 };
  const spdx3sec = detectSPDX3Security(input);
  if (spdx3sec > 0) return { format: 'spdx-3-security', confidence: spdx3sec };
  const spdx = detectSPDX(input);
  if (spdx > 0) return { format: 'spdx', confidence: spdx };
  return undefined;
}
