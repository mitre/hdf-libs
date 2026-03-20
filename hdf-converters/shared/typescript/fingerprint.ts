/**
 * Converter auto-detection dispatcher.
 *
 * Walks registered fingerprints and returns the highest-confidence match.
 * Lightweight — no converter imports, safe for any bundle.
 */

import { getIngestFingerprints, type ConverterFingerprint, type InputFamily } from './registry.js';

export interface DetectionResult {
  fingerprint: ConverterFingerprint;
  confidence: number;
}

export function detectConverter(input: string): DetectionResult | undefined {
  return detectConverterAll(input)[0];
}

export function detectConverterAll(input: string): DetectionResult[] {
  const family = detectFamily(input);
  if (!family) return [];

  const parsed = family === 'json' ? tryParseJSON(input) : input;
  if (parsed === undefined) return [];

  const results: DetectionResult[] = [];
  for (const fp of getIngestFingerprints()) {
    if (fp.inputFamily !== family) continue;
    const confidence = fp.fingerprint(parsed);
    if (confidence > 0) {
      results.push({ fingerprint: fp, confidence });
    }
  }

  results.sort((a, b) => b.confidence - a.confidence);
  return results;
}

export function detectFamily(input: string): InputFamily | undefined {
  if (!input) return undefined;
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (trimmed.startsWith('<')) return 'xml';
  return 'text';
}

function tryParseJSON(input: string): unknown | undefined {
  try {
    return JSON.parse(input);
  } catch {
    return undefined;
  }
}
