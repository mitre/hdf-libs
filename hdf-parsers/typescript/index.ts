import type { HDFResults, HDFBaseline } from '@mitre/hdf-schema';
export { flattenOverlays } from './flatten.js';
export type { FlattenResult, FlattenMetadata, BaselineMerge } from './flatten.js';
import { validateResults, validateBaseline, validate as autoValidate } from '@mitre/hdf-validators';

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
  const jsonStr = typeof input === 'string' ? input : new TextDecoder().decode(input);

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

  // Check for trailing garbage by re-serializing and comparing length
  // This catches cases like: {"valid":"json"}garbage
  const serialized = JSON.stringify(data);
  const trimmedInput = jsonStr.trim();
  if (serialized.length !== trimmedInput.length && !isWhitespaceEquivalent(serialized, trimmedInput)) {
    return {
      success: false,
      error: 'Invalid JSON: unexpected trailing data after end of object'
    };
  }

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
  const jsonStr = typeof input === 'string' ? input : new TextDecoder().decode(input);

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

  // Check for trailing garbage
  const serialized = JSON.stringify(data);
  const trimmedInput = jsonStr.trim();
  if (serialized.length !== trimmedInput.length && !isWhitespaceEquivalent(serialized, trimmedInput)) {
    return {
      success: false,
      error: 'Invalid JSON: unexpected trailing data after end of object'
    };
  }

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
  const jsonStr = typeof input === 'string' ? input : new TextDecoder().decode(input);

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

  // Check for trailing garbage
  const serialized = JSON.stringify(data);
  const trimmedInput = jsonStr.trim();
  if (serialized.length !== trimmedInput.length && !isWhitespaceEquivalent(serialized, trimmedInput)) {
    return {
      success: false,
      error: 'Invalid JSON: unexpected trailing data after end of object'
    };
  }

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

/**
 * Check if two JSON strings are equivalent modulo whitespace
 * This is a simple heuristic - we check if one is just whitespace-padded version of other
 */
function isWhitespaceEquivalent(a: string, b: string): boolean {
  // Remove all whitespace and compare
  const normalizeWhitespace = (s: string): string => s.replace(/\s+/g, '');
  return normalizeWhitespace(a) === normalizeWhitespace(b);
}
