/**
 * CSV parsing and generation utilities using papaparse
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
 * @param data - Array of objects to convert to CSV
 * @param options - Optional papaparse unparse configuration
 * @returns CSV string
 */
export function buildCsv<T = Record<string, unknown>>(
  data: T[],
  options?: Partial<UnparseConfig>
): string {
  const mergedOptions = {
    ...DEFAULT_BUILD_OPTIONS,
    ...options,
  };

  return Papa.unparse(data, mergedOptions);
}

/**
 * Build CSV string from array of arrays
 * @param data - Array of arrays to convert to CSV
 * @param options - Optional papaparse unparse configuration
 * @returns CSV string
 */
export function buildCsvArray(
  data: string[][],
  options?: Partial<UnparseConfig>
): string {
  const mergedOptions = {
    ...DEFAULT_BUILD_OPTIONS,
    header: false,
    ...options,
  };

  return Papa.unparse(data, mergedOptions);
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
