// Document loader engine core — the TypeScript peer of hdf-engine/go/loader.go,
// kept at behavioural parity (see loader.test.ts + the Go parity test, which
// run both over the same fixtures). Pure and schema-typed: size-guard first,
// wire-format + document-type detection, then the canonical parse for the
// results/baseline types. No cache, no degraded envelope — those are MCP
// concerns layered on top in hdf-cli/internal/mcp/loader.

import type { HDFResults, HDFBaseline } from '@mitre/hdf-schema';
import { validateInputSize } from '@mitre/hdf-utilities';
import { parseResults, parseBaseline } from '@mitre/hdf-parsers';
import { detect, type HdfDocType } from './detect.js';

/** Wire encoding of loader input (parity with Go InputFormat). */
export type InputFormat = 'json' | 'ndjson';

export interface LoadResult {
  format: InputFormat;
  docType: HdfDocType;
  results?: HDFResults;
  baseline?: HDFBaseline;
  /** Non-empty when detected as results/baseline but the parse/validate failed. */
  parseError?: string;
  valid: boolean;
}

/**
 * load is the schema-typed loader core. In order: validateInputSize (FIRST,
 * before any parse; maxSize <= 0 uses the default), wire-format detection
 * (JSON vs NDJSON), document-type detection (detect), then the canonical
 * hdf-parsers parse for the results and baseline types. Other types are
 * detected but not parsed here.
 */
export function load(input: string | Uint8Array, maxSize = 0): LoadResult {
  validateInputSize(input, maxSize); // first op — throws on oversize

  const text = typeof input === 'string' ? input : new TextDecoder().decode(input);
  const result: LoadResult = {
    format: detectFormat(text),
    docType: detect(text),
    valid: false,
  };

  if (result.docType === 'results') {
    const r = parseResults(text);
    if (r.success && r.data) {
      result.results = r.data;
      result.valid = true;
    } else {
      result.parseError = r.error;
    }
  } else if (result.docType === 'baseline') {
    const r = parseBaseline(text);
    if (r.success && r.data) {
      result.baseline = r.data;
      result.valid = true;
    } else {
      result.parseError = r.error;
    }
  }

  return result;
}

/**
 * detectFormat classifies input as a single JSON document or newline-delimited
 * JSON, consistent with the Go core: NDJSON is two or more non-blank lines that
 * each independently parse as a complete JSON value. A pretty-printed single
 * object stays 'json' (its first line is not itself a complete JSON value).
 */
export function detectFormat(text: string): InputFormat {
  const lines = text.split('\n').filter((l) => l.trim() !== '');
  const [first, second] = lines;
  if (first === undefined || second === undefined) {
    return 'json';
  }
  if (isCompleteJSON(first) && isCompleteJSON(second)) {
    return 'ndjson';
  }
  return 'json';
}

// isCompleteJSON reports whether s is a single complete JSON value with no
// trailing content — the per-line test the NDJSON classifier applies. JSON.parse
// already rejects trailing garbage, so a successful parse is sufficient.
function isCompleteJSON(s: string): boolean {
  try {
    JSON.parse(s);
    return true;
  } catch {
    return false;
  }
}
