export { canonicalJson, canonicalChecksum } from './canonical.js';
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

/**
 * Render a JSON number as text the way Go's strconv.FormatFloat(v, 'f', -1, 64)
 * does: shortest round-trip digits, positional always, never exponent notation.
 *
 * JavaScript's own Number-to-string switches to exponent at and above 1e21 and
 * below 1e-6, and drops the sign of negative zero, so a converter that emits
 * String(n) diverges from its Go peer at both magnitude extremes and at -0.
 * Expansion works on the digit string rather than toFixed, which caps at 100
 * fraction digits and so cannot render the smallest denormals at all.
 */
export function formatJsonNumber(value: number): string {
  if (Object.is(value, -0)) return '-0';
  if (!Number.isFinite(value)) return String(value);

  const rendered = String(value);
  const exponent = rendered.indexOf('e');
  if (exponent < 0) return rendered;

  const negative = rendered.startsWith('-');
  const significand = rendered.slice(negative ? 1 : 0, exponent);
  const power = Number(rendered.slice(exponent + 1));
  const point = significand.indexOf('.');
  const digits = point < 0 ? significand : significand.slice(0, point) + significand.slice(point + 1);
  // Where the decimal point lands once the exponent is applied, counted from the
  // left of the digit string; <= 0 means the value is entirely below the point.
  const position = (point < 0 ? significand.length : point) + power;

  let out: string;
  if (position <= 0) {
    out = `0.${'0'.repeat(-position)}${digits}`;
  } else if (position >= digits.length) {
    out = digits + '0'.repeat(position - digits.length);
  } else {
    out = `${digits.slice(0, position)}.${digits.slice(position)}`;
  }
  return negative ? `-${out}` : out;
}
