/**
 * @mitre/hdf-utilities
 * Utility functions for HDF libraries
 */

// JSON utilities
export { parseJSON, stringifyJSON, isValidJSON, type StringifyOptions } from './json/index.js';

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
  type CsvParseOptions,
  type CsvBuildOptions,
} from './csv/index.js';
