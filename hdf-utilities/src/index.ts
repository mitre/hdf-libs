/**
 * @mitre/hdf-utilities
 * Utility functions for HDF libraries
 */

// JSON utilities
export { parseJSON, stringifyJSON, isValidJSON, findJsonValues, type StringifyOptions } from './json/index.js';

// Hash utilities
export {
  generateHash,
  sha256,
  sha512,
  hashObject,
  verifyHash,
  type HashAlgorithm,
  type HashEncoding,
  type HashOptions,
} from './hash/index.js';

// XML utilities
export {
  parseXml,
  buildXml,
  isValidXml,
  parseXmlWithArrays,
  extractTextFromXml,
  findXmlValues,
} from './xml/index.js';

// CSV utilities
export {
  parseCsv,
  parseCsvArray,
  buildCsv,
  buildCsvArray,
  isValidCsv,
  sanitizeCsvValue,
  sanitizeCsvArray,
  sanitizeCsvObject,
  extractCsvColumn,
  findCsvRows,
  type CsvParseOptions,
  type CsvBuildOptions,
} from './csv/index.js';

// Object utilities (generic traversal)
export { findValuesByKey, extractColumn, findRows } from './object/index.js';

// String utilities
export { stripHtml, parseTimestamp } from './string/index.js';

// Severity/impact mapping
export { severityToImpact, impactToSeverity, cvssScoreToSeverity } from './severity/index.js';

// CVSS vector parsing + validation
export {
  parseCvssVector,
  validateCvssVector,
  type ParsedCvssVector,
  type CvssValidationResult,
} from './cvss/index.js';

// CPE 2.3 URI parser
export { parseCpe, type ParsedCpe, type CpePart } from './cpe/index.js';

// PURL (Package URL) parser
export { parsePurl, type ParsedPurl } from './purl/index.js';
