export { findValuesByKey as findJsonValues } from '../object/index.js';

/**
 * Options for JSON stringification
 */
export interface StringifyOptions {
  /** Enable pretty printing with indentation */
  pretty?: boolean;
  /** Number of spaces for indentation (default: 2) */
  indent?: number;
}

/**
 * Safely parse a JSON string
 * @param input - JSON string to parse
 * @returns Parsed JSON value
 * @throws Error if input is not valid JSON
 */
export function parseJSON<T = unknown>(input: string): T {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  if (input.trim() === '') {
    throw new Error('Input cannot be empty');
  }

  try {
    return JSON.parse(input) as T;
  } catch (error) {
    throw new Error(`Invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Safely stringify a value to JSON
 * @param value - Value to stringify
 * @param options - Stringification options
 * @returns JSON string
 * @throws Error if value contains circular references or cannot be stringified
 */
export function stringifyJSON(value: unknown, options: StringifyOptions = {}): string {
  const { pretty = false, indent = 2 } = options;

  try {
    if (pretty) {
      return JSON.stringify(value, null, indent);
    }
    return JSON.stringify(value);
  } catch (error) {
    throw new Error(`Failed to stringify JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Check if a string is valid JSON
 * @param input - String to validate
 * @returns true if input is valid JSON, false otherwise
 */
export function isValidJSON(input: unknown): boolean {
  if (typeof input !== 'string') {
    return false;
  }

  if (input.trim() === '') {
    return false;
  }

  try {
    JSON.parse(input);
    return true;
  } catch {
    return false;
  }
}
