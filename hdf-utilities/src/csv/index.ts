/**
 * CSV parsing and generation utilities using papaparse
 *
 * SECURITY WARNING: CSV files opened in Excel/LibreOffice may execute formulas.
 * Use sanitization options when exporting data that may contain user-controlled content.
 */

import Papa from 'papaparse';
import type { ParseConfig, UnparseConfig } from 'papaparse';

/**
 * Default options for parsing CSV with headers
 */
const DEFAULT_PARSE_OPTIONS: ParseConfig = {
  header: true,
  skipEmptyLines: true,
  transformHeader: undefined,
  dynamicTyping: false,
};

/**
 * Default options for parsing CSV without headers
 */
const DEFAULT_PARSE_ARRAY_OPTIONS: ParseConfig = {
  header: false,
  skipEmptyLines: true,
  dynamicTyping: false,
};

/**
 * Default options for building CSV
 */
const DEFAULT_BUILD_OPTIONS: UnparseConfig = {
  header: true,
  newline: '\n',
  skipEmptyLines: true,
};

/**
 * Parse CSV string into array of objects with headers as keys
 * @param csv - CSV string to parse
 * @param options - Optional papaparse configuration
 * @returns Array of objects representing rows
 * @throws Error if parsing fails
 */
export function parseCsv<T = Record<string, unknown>>(
  csv: string,
  options?: Partial<ParseConfig>
): T[] {
  const mergedOptions = {
    ...DEFAULT_PARSE_OPTIONS,
    ...options,
  };

  const result = Papa.parse<T>(csv.trim(), mergedOptions);

  if (result.errors.length > 0) {
    const errorMessages = result.errors
      .map((err) => `Row ${err.row}: ${err.message}`)
      .join('; ');
    throw new Error(`CSV parsing failed: ${errorMessages}`);
  }

  return result.data;
}

/**
 * Parse CSV string into array of arrays without treating first row as headers
 * @param csv - CSV string to parse
 * @param options - Optional papaparse configuration
 * @returns Array of arrays representing rows
 * @throws Error if parsing fails
 */
export function parseCsvArray(
  csv: string,
  options?: Partial<ParseConfig>
): string[][] {
  const mergedOptions = {
    ...DEFAULT_PARSE_ARRAY_OPTIONS,
    ...options,
  };

  const result = Papa.parse<string[]>(csv.trim(), mergedOptions);

  if (result.errors.length > 0) {
    const errorMessages = result.errors
      .map((err) => `Row ${err.row}: ${err.message}`)
      .join('; ');
    throw new Error(`CSV parsing failed: ${errorMessages}`);
  }

  return result.data;
}

/**
 * Build CSV string from array of objects
 *
 * SECURITY: Set sanitize=true when data may contain user-controlled content
 * to prevent CSV formula injection attacks in Excel/LibreOffice.
 *
 * @param data - Array of objects to convert to CSV
 * @param options - Optional papaparse configuration and sanitize flag
 * @returns CSV string
 *
 * @example
 * ```typescript
 * // Without sanitization (default)
 * buildCsv([{name: '=1+1', value: 'test'}]);
 *
 * // With sanitization (recommended for user data)
 * buildCsv([{name: '=1+1', value: 'test'}], { sanitize: true });
 * // Result: '=1+1' becomes "'=1+1"
 * ```
 */
export function buildCsv<T = Record<string, unknown>>(
  data: T[],
  options?: Partial<UnparseConfig> & { sanitize?: boolean }
): string {
  const { sanitize, ...unparseOptions } = options || {};

  const mergedOptions = {
    ...DEFAULT_BUILD_OPTIONS,
    ...unparseOptions,
  };

  let processedData = data;
  if (sanitize) {
    processedData = data.map((row) =>
      sanitizeCsvObject(row as Record<string, unknown>)
    ) as T[];
  }

  return Papa.unparse(processedData, mergedOptions);
}

/**
 * Build CSV string from array of arrays
 *
 * SECURITY: Set sanitize=true when data may contain user-controlled content
 * to prevent CSV formula injection attacks in Excel/LibreOffice.
 *
 * @param data - Array of arrays to convert to CSV
 * @param options - Optional papaparse configuration and sanitize flag
 * @returns CSV string
 *
 * @example
 * ```typescript
 * // With sanitization for security tool output
 * const rows = [['Title', 'Description'], ['Test', '=cmd|calc']];
 * buildCsvArray(rows, { sanitize: true });
 * ```
 */
export function buildCsvArray(
  data: string[][],
  options?: Partial<UnparseConfig> & { sanitize?: boolean }
): string {
  const { sanitize, ...unparseOptions } = options || {};

  const mergedOptions = {
    ...DEFAULT_BUILD_OPTIONS,
    header: false,
    ...unparseOptions,
  };

  let processedData = data;
  if (sanitize) {
    processedData = data.map((row) => sanitizeCsvArray(row));
  }

  return Papa.unparse(processedData, mergedOptions);
}

/**
 * Validate CSV format
 * @param csv - CSV string to validate
 * @returns True if valid CSV, false otherwise
 */
export function isValidCsv(csv: string): boolean {
  if (!csv || csv.trim().length === 0) {
    return false;
  }

  const result = Papa.parse(csv.trim(), {
    preview: 1,
    skipEmptyLines: true,
  });

  return result.errors.length === 0;
}

/**
 * Sanitize a single CSV value to prevent formula injection
 *
 * Prefixes values starting with =, +, -, @, |, or % with a single quote
 * to prevent Excel/LibreOffice from interpreting them as formulas.
 *
 * @param value - Value to sanitize
 * @returns Sanitized value
 *
 * @example
 * ```typescript
 * sanitizeCsvValue('=1+1'); // Returns: '=1+1'
 * sanitizeCsvValue('normal'); // Returns: 'normal'
 * ```
 */
export function sanitizeCsvValue(value: unknown): string {
  const str = String(value);
  // Check if string starts with formula trigger characters
  if (/^[=+\-@|%]/.test(str)) {
    return `'${str}`;
  }
  return str;
}

/**
 * Sanitize all values in an array to prevent formula injection
 *
 * @param values - Array of values to sanitize
 * @returns Array with sanitized values
 */
export function sanitizeCsvArray(values: unknown[]): string[] {
  return values.map(sanitizeCsvValue);
}

/**
 * Sanitize all values in an object to prevent formula injection
 *
 * @param obj - Object with values to sanitize
 * @returns New object with sanitized values
 */
export function sanitizeCsvObject<T extends Record<string, unknown>>(
  obj: T
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[key] = sanitizeCsvValue(value);
  }
  return sanitized;
}
