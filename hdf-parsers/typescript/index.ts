import type { HDFResults, HDFBaseline } from '@mitre/hdf-schema';
export { flattenOverlays } from './flatten.js';
export type { FlattenResult, FlattenMetadata, BaselineMerge } from './flatten.js';
import { validateResults, validateBaseline, validate as autoValidate } from '@mitre/hdf-validators';

// JSON-quoted ISO 8601 timestamp with no trailing timezone — InSpec emits
// these (e.g. "2026-03-25T22:56:27.736808"). ajv-formats requires RFC 3339
// for `date-time` and rejects them.
const NO_TZ_TIMESTAMP_REGEX = /"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)"/g;

/**
 * Append Z (treat as UTC) to bare ISO timestamps in a JSON string so they
 * pass schema validation. Exported so other workspace packages can use the
 * same regex instead of re-implementing it. Matches the Go side at
 * hdf-parsers/go/parsers.go.
 */
export function normalizeTimestamps(input: string): string {
  return input.replace(NO_TZ_TIMESTAMP_REGEX, '"$1Z"');
}

/**
 * Result of parsing operation
 */
export interface ParseResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  type?: 'results' | 'baseline';
}

/**
 * Parse HDF Results document from string or bytes
 * @param input - JSON string or Uint8Array to parse
 * @returns ParseResult with parsed data or error
 */
export function parseResults(input: string | Uint8Array): ParseResult<HDFResults> {
  // Convert Uint8Array to string if needed
  const decoded = typeof input === 'string' ? input : new TextDecoder().decode(input);
  const jsonStr = normalizeTimestamps(decoded);

  // Check for empty input
  if (jsonStr.trim().length === 0) {
    return {
      success: false,
      error: 'Input is empty'
    };
  }

  // Parse JSON
  let data: unknown;
  try {
    data = JSON.parse(jsonStr);
  } catch (err) {
    return {
      success: false,
      error: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}`
    };
  }

  // JSON.parse already rejects trailing garbage (it throws on the first
  // non-whitespace byte after the root value), so the catch above covers
  // that case. A prior length-compare heuristic here false-positived on
  // complex real-world inputs (e.g. `0.70` parsed as `0.7` would re-
  // serialize to a different length) — caught by the cross-language
  // parser parity test in typescript/parse-equivalence.test.ts.

  // Validate against schema
  const validationResult = validateResults(data);
  if (!validationResult.valid) {
    return {
      success: false,
      error: `Schema validation failed: ${validationResult.getErrorMessage()}`
    };
  }

  return {
    success: true,
    data: data as HDFResults
  };
}

/**
 * Parse HDF Baseline document from string or bytes
 * @param input - JSON string or Uint8Array to parse
 * @returns ParseResult with parsed data or error
 */
export function parseBaseline(input: string | Uint8Array): ParseResult<HDFBaseline> {
  // Convert Uint8Array to string if needed
  const decoded = typeof input === 'string' ? input : new TextDecoder().decode(input);
  const jsonStr = normalizeTimestamps(decoded);

  // Check for empty input
  if (jsonStr.trim().length === 0) {
    return {
      success: false,
      error: 'Input is empty'
    };
  }

  // Parse JSON
  let data: unknown;
  try {
    data = JSON.parse(jsonStr);
  } catch (err) {
    return {
      success: false,
      error: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}`
    };
  }

  // Trailing garbage already caught by the JSON.parse catch above; see
  // parseResults for the full rationale.

  // Validate against schema
  const validationResult = validateBaseline(data);
  if (!validationResult.valid) {
    return {
      success: false,
      error: `Schema validation failed: ${validationResult.getErrorMessage()}`
    };
  }

  return {
    success: true,
    data: data as HDFBaseline
  };
}

/**
 * Parse HDF document with auto-detection of type
 * @param input - JSON string or Uint8Array to parse
 * @returns ParseResult with parsed data, type indicator, or error
 */
export function parse(input: string | Uint8Array): ParseResult<HDFResults | HDFBaseline> {
  // Convert Uint8Array to string if needed
  const decoded = typeof input === 'string' ? input : new TextDecoder().decode(input);
  const jsonStr = normalizeTimestamps(decoded);

  // Check for empty input
  if (jsonStr.trim().length === 0) {
    return {
      success: false,
      error: 'Input is empty'
    };
  }

  // Parse JSON
  let data: unknown;
  try {
    data = JSON.parse(jsonStr);
  } catch (err) {
    return {
      success: false,
      error: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}`
    };
  }

  // Trailing garbage already caught by the JSON.parse catch above; see
  // parseResults for the full rationale.

  // Auto-validate and detect type
  const validationResult = autoValidate(data);
  if (!validationResult.valid) {
    return {
      success: false,
      error: `Schema validation failed: ${validationResult.getErrorMessage()}`
    };
  }

  // Determine type based on structure
  if (typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>;

    // HDF Results has 'baselines' array at root
    if ('baselines' in obj) {
      return {
        success: true,
        data: data as HDFResults,
        type: 'results'
      };
    }

    // HDF Baseline has 'name' and 'requirements' at root
    if ('name' in obj && 'requirements' in obj) {
      return {
        success: true,
        data: data as HDFBaseline,
        type: 'baseline'
      };
    }
  }

  return {
    success: false,
    error: 'Unable to determine HDF document type'
  };
}

