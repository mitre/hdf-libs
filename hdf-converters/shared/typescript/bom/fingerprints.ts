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

/** CycloneDX: bomFormat === 'CycloneDX'. Returns 0..1 confidence. */
export function detectCycloneDX(input: unknown): number {
  const obj = record(input);
  return obj?.bomFormat === 'CycloneDX' ? 1 : 0;
}

/**
 * CycloneDX ML-BOM: a CycloneDX document with at least one
 * machine-learning-model component. Strictly more specific than plain
 * CycloneDX.
 */
export function detectCycloneDXML(input: unknown): number {
  const obj = record(input);
  if (obj?.bomFormat !== 'CycloneDX') return 0;
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
 * Detect the BOM format of a parsed JSON object. ML wins over plain CycloneDX
 * by precedence; returns undefined when no supported format matches.
 */
export function detectFormat(input: unknown): FormatDetection | undefined {
  const ml = detectCycloneDXML(input);
  if (ml > 0) return { format: 'cyclonedx-ml', confidence: ml };
  const cdx = detectCycloneDX(input);
  if (cdx > 0) return { format: 'cyclonedx', confidence: cdx };
  const spdx = detectSPDX(input);
  if (spdx > 0) return { format: 'spdx', confidence: spdx };
  return undefined;
}
