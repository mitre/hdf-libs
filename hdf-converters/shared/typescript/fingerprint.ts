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
  /** Detected format version (e.g. "2.1.0" for SARIF). Empty when not available. */
  version: string;
}

/** Minimum confidence to accept an auto-detection result. */
const MIN_CONFIDENCE = 0.8;

export function detectConverter(input: string): DetectionResult | undefined {
  const results = detectConverterAll(input);
  if (results.length === 0) return undefined;
  const best = results[0]!;
  // Refuse to guess if confidence is too low
  if (best.confidence < MIN_CONFIDENCE) return undefined;
  // Refuse to guess if there's an ambiguous tie at the top
  if (results.length > 1 && results[1]!.confidence === best.confidence) return undefined;
  return best;
}

/** Maximum input size for fingerprint detection (100 MB). */
const MAX_DETECT_SIZE = 100 * 1024 * 1024;
/** Maximum characters scanned for XML/text root element detection. */
const MAX_XML_PREAMBLE = 8 * 1024;

export function detectConverterAll(input: string): DetectionResult[] {
  if (!input || input.length > MAX_DETECT_SIZE) return [];

  // Strip a leading UTF-8 BOM so direct library callers (e.g. heimdall passing
  // raw input) detect BOM-prefixed JSON/XML; the CLI strips it earlier too.
  input = input.replace(/^\uFEFF/, '');

  const family = detectFamily(input);
  if (!family) return [];

  // For XML/text, only pass the preamble to fingerprints
  const effectiveInput = (family !== 'json' && input.length > MAX_XML_PREAMBLE)
    ? input.slice(0, MAX_XML_PREAMBLE)
    : input;

  const parsed = family === 'json' ? tryParseJSON(input) : effectiveInput;
  if (parsed === undefined) return [];

  const results: DetectionResult[] = [];
  for (const fp of getIngestFingerprints()) {
    if (fp.inputFamily !== family) continue;
    const confidence = fp.fingerprint(parsed);
    if (confidence > 0) {
      let version = '';
      if (fp.detectVersion) {
        try {
          version = fp.detectVersion(parsed);
        } catch {
          version = '';
        }
      }
      results.push({ fingerprint: fp, confidence, version });
    }
  }

  // Stable sort: by confidence desc, then by ID asc for deterministic tiebreaking
  results.sort((a, b) => b.confidence - a.confidence || a.fingerprint.id.localeCompare(b.fingerprint.id));
  return results;
}

export function detectFamily(input: string): InputFamily | undefined {
  if (!input) return undefined;
  // Strip UTF-8 BOM (U+FEFF) — common on Windows-generated files
  const stripped = input.replace(/^\uFEFF/, '');
  const trimmed = stripped.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (trimmed.startsWith('<')) return 'xml';
  // CSV intentionally excluded — too many false positives (see design doc D1)
  return 'text';
}

function tryParseJSON(input: string): unknown | undefined {
  try {
    return JSON.parse(input);
  } catch {
    return undefined;
  }
}
