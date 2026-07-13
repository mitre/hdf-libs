/**
 * CSV parsing and generation utilities using d3-dsv
 *
 * SECURITY WARNING: CSV files opened in Excel/LibreOffice may execute formulas.
 * Use sanitization options when exporting data that may contain user-controlled content.
 */

import { dsvFormat } from 'd3-dsv';

export {
  extractColumn as extractCsvColumn,
  findRows as findCsvRows,
} from '../object/index.js';

/**
 * Options for parsing CSV
 */
export interface CsvParseOptions {
  header?: boolean;
  skipEmptyLines?: boolean;
  transformHeader?: (header: string, index: number) => string;
  dynamicTyping?: boolean;
  delimiter?: string;
  maxSize?: number;
}

/**
 * Options for building CSV
 */
export interface CsvBuildOptions {
  header?: boolean;
  newline?: string;
  skipEmptyLines?: boolean;
  delimiter?: string;
}

/**
 * Default options for parsing CSV with headers
 */
const DEFAULT_PARSE_OPTIONS: CsvParseOptions = {
  header: true,
  skipEmptyLines: true,
  transformHeader: undefined,
  dynamicTyping: false,
};

/**
 * Default options for parsing CSV without headers
 */
const DEFAULT_PARSE_ARRAY_OPTIONS: CsvParseOptions = {
  header: false,
  skipEmptyLines: true,
  dynamicTyping: false,
};

/**
 * Default options for building CSV
 */
const DEFAULT_BUILD_OPTIONS: CsvBuildOptions = {
  header: true,
  newline: '\n',
  skipEmptyLines: true,
};

/**
 * Validate CSV quoting — throws if unclosed quotes are found
 */
function validateQuoting(csv: string): void {
  let inQuotes = false;
  let row = 0;
  for (let i = 0; i < csv.length; i++) {
    if (csv[i] === '"') {
      if (inQuotes && i + 1 < csv.length && csv[i + 1] === '"') {
        i++; // skip escaped quote ""
      } else {
        inQuotes = !inQuotes;
      }
    } else if (csv[i] === '\n' && !inQuotes) {
      row++;
    }
  }
  if (inQuotes) {
    throw new Error(`CSV parsing failed: Row ${row}: Unclosed quote`);
  }
}

/**
 * Convert string value to number or boolean when appropriate
 */
function dynamicTypeConvert(value: string): unknown {
  if (value === '') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  const num = Number(value);
  if (!isNaN(num) && value.trim() !== '') return num;
  return value;
}

/**
 * Parse CSV string into array of objects with headers as keys
 * @param csv - CSV string to parse
 * @param options - Optional parse configuration
 * @returns Array of objects representing rows
 * @throws Error if parsing fails
 */
export function parseCsv<T = Record<string, unknown>>(
  csv: string,
  options?: Partial<CsvParseOptions>
): T[] {
  if (options?.maxSize !== undefined && csv.length > options.maxSize) {
    throw new Error(
      `Input exceeds maximum allowed size: ${csv.length} bytes exceeds limit of ${options.maxSize} bytes`
    );
  }

  const opts = { ...DEFAULT_PARSE_OPTIONS, ...options };
  const trimmed = csv.trim();

  validateQuoting(trimmed);

  const dsv = dsvFormat(opts.delimiter ?? ',');
  const parsed = dsv.parse(trimmed);
  const { columns } = parsed;

  // Pre-compute transformed headers
  const headers = opts.transformHeader
    ? columns.map((col, i) => opts.transformHeader!(col, i))
    : columns;

  let rows: Record<string, unknown>[] = parsed.map((row) => {
    const obj: Record<string, unknown> = {};
    columns.forEach((col, i) => {
      let value: unknown = row[col] ?? '';
      if (opts.dynamicTyping && typeof value === 'string') {
        value = dynamicTypeConvert(value);
      }
      const key = headers[i];
      if (key !== undefined) {
        obj[key] = value;
      }
    });
    return obj;
  });

  if (opts.skipEmptyLines) {
    rows = rows.filter((row) =>
      Object.values(row).some((v) => v !== '' && v !== null && v !== undefined)
    );
  }

  return rows as T[];
}

/**
 * Parse CSV string into array of arrays without treating first row as headers
 * @param csv - CSV string to parse
 * @param options - Optional parse configuration
 * @returns Array of arrays representing rows
 * @throws Error if parsing fails
 */
export function parseCsvArray(
  csv: string,
  options?: Partial<CsvParseOptions>
): string[][] {
  if (options?.maxSize !== undefined && csv.length > options.maxSize) {
    throw new Error(
      `Input exceeds maximum allowed size: ${csv.length} bytes exceeds limit of ${options.maxSize} bytes`
    );
  }

  const opts = { ...DEFAULT_PARSE_ARRAY_OPTIONS, ...options };
  const trimmed = csv.trim();

  validateQuoting(trimmed);

  const dsv = dsvFormat(opts.delimiter ?? ',');
  let rows = dsv.parseRows(trimmed);

  if (opts.skipEmptyLines) {
    rows = rows.filter((row) => !(row.length === 1 && row[0] === ''));
  }

  return rows;
}

/**
 * Build CSV string from array of objects
 *
 * SECURITY: Set sanitize=true when data may contain user-controlled content
 * to prevent CSV formula injection attacks in Excel/LibreOffice.
 *
 * @param data - Array of objects to convert to CSV
 * @param options - Optional build configuration and sanitize flag
 * @returns CSV string
 */
export function buildCsv<T = Record<string, unknown>>(
  data: T[],
  options?: Partial<CsvBuildOptions> & { sanitize?: boolean }
): string {
  const { sanitize, ...buildOpts } = options || {};
  const opts = { ...DEFAULT_BUILD_OPTIONS, ...buildOpts };

  if (data.length === 0) return '';

  let processedData = data;
  if (sanitize) {
    processedData = data.map((row) =>
      sanitizeCsvObject(row as Record<string, unknown>)
    ) as T[];
  }

  const dsv = dsvFormat(opts.delimiter ?? ',');
  let result: string;

  if (opts.header === false) {
    const rows = processedData.map((row) =>
      Object.values(row as Record<string, unknown>).map(String)
    );
    result = dsv.formatRows(rows);
  } else {
    result = dsv.format(processedData as Record<string, unknown>[]);
  }

  result = terminateFinalRecord(result);

  if (opts.newline && opts.newline !== '\n') {
    result = result.replace(/\n/g, opts.newline);
  }

  return result;
}

/**
 * Terminate the final record with a newline. d3-dsv leaves it off, but Go's
 * encoding/csv (which the Go converters use) always writes it, so without this
 * every TS CSV would differ from its Go twin by exactly one trailing byte.
 * Applied before the newline substitution so a \r\n dialect gets it too.
 */
function terminateFinalRecord(csv: string): string {
  return csv.endsWith('\n') ? csv : `${csv}\n`;
}

/**
 * Build CSV string from array of arrays
 *
 * SECURITY: Set sanitize=true when data may contain user-controlled content
 * to prevent CSV formula injection attacks in Excel/LibreOffice.
 *
 * @param data - Array of arrays to convert to CSV
 * @param options - Optional build configuration and sanitize flag
 * @returns CSV string
 */
export function buildCsvArray(
  data: string[][],
  options?: Partial<CsvBuildOptions> & { sanitize?: boolean }
): string {
  const { sanitize, ...buildOpts } = options || {};
  const opts = { ...DEFAULT_BUILD_OPTIONS, header: false, ...buildOpts };

  if (data.length === 0) return '';

  let processedData = data;
  if (sanitize) {
    processedData = data.map((row) => sanitizeCsvArray(row));
  }

  const dsv = dsvFormat(opts.delimiter ?? ',');
  let result = terminateFinalRecord(dsv.formatRows(processedData));

  if (opts.newline && opts.newline !== '\n') {
    result = result.replace(/\n/g, opts.newline);
  }

  return result;
}

/**
 * Validate CSV format
 * @param csv - CSV string to validate
 * @returns True if valid CSV, false otherwise
 */
export function isValidCsv(csv: string): boolean {
  if (!csv || csv.trim().length === 0) return false;

  const trimmed = csv.trim();

  // CSV must have at least one delimiter (comma) to be considered CSV structure
  if (!trimmed.includes(',')) return false;

  try {
    validateQuoting(trimmed);
  } catch {
    return false;
  }

  return true;
}

/**
 * Sanitize a single CSV value to prevent formula injection
 *
 * Prefixes values starting with =, +, -, @, |, or % with a single quote
 * to prevent Excel/LibreOffice from interpreting them as formulas.
 *
 * @param value - Value to sanitize
 * @returns Sanitized value
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
