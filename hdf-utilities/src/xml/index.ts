/**
 * XML parsing utilities for HDF converters
 * Provides XML parsing with sensible defaults for security tool output
 */

import { XMLParser, XMLBuilder, X2jOptions, XmlBuilderOptions, XMLValidator } from 'fast-xml-parser';

/**
 * Default options for XML parsing optimized for security tool converters
 */
const DEFAULT_PARSE_OPTIONS: Partial<X2jOptions> = {
  attributeNamePrefix: '',
  textNodeName: '#text',
  ignoreAttributes: false,
  ignoreDeclaration: true,
  parseAttributeValue: false,
  parseTagValue: false,
  removeNSPrefix: true,
};

/**
 * Default options for XML building
 */
const DEFAULT_BUILD_OPTIONS: Partial<XmlBuilderOptions> = {
  attributeNamePrefix: '',
  textNodeName: '#text',
  ignoreAttributes: false,
  format: true,
  indentBy: '  ',
  suppressEmptyNode: false,
};

/**
 * Parse XML string to JavaScript object
 *
 * @param xml - XML string to parse
 * @param options - Optional parser configuration (merged with defaults)
 * @returns Parsed JavaScript object
 *
 * @example
 * ```typescript
 * const xmlString = '<root><item id="1">Test</item></root>';
 * const result = parseXml(xmlString);
 * // Returns: { root: { item: { id: '1', '#text': 'Test' } } }
 * ```
 */
export function parseXml(
  xml: string,
  options?: Partial<X2jOptions>
): Record<string, unknown> {
  const mergedOptions = {
    ...DEFAULT_PARSE_OPTIONS,
    ...options,
  };

  const parser = new XMLParser(mergedOptions);
  return parser.parse(xml) as Record<string, unknown>;
}

/**
 * Build XML string from JavaScript object
 *
 * @param obj - JavaScript object to convert to XML
 * @param options - Optional builder configuration (merged with defaults)
 * @returns XML string
 *
 * @example
 * ```typescript
 * const obj = { root: { item: { id: '1', '#text': 'Test' } } };
 * const xml = buildXml(obj);
 * // Returns formatted XML string
 * ```
 */
export function buildXml(
  obj: Record<string, unknown>,
  options?: Partial<XmlBuilderOptions>
): string {
  const mergedOptions = {
    ...DEFAULT_BUILD_OPTIONS,
    ...options,
  };

  const builder = new XMLBuilder(mergedOptions);
  return builder.build(obj) as string;
}

/**
 * Validate if a string is well-formed XML
 *
 * @param xml - String to validate
 * @returns True if valid XML, false otherwise
 *
 * @example
 * ```typescript
 * isValidXml('<root><item>Test</item></root>'); // true
 * isValidXml('<root><item>Test</root>'); // false (mismatched tags)
 * isValidXml('not xml'); // false
 * ```
 */
export function isValidXml(xml: string): boolean {
  if (!xml || xml.trim().length === 0) {
    return false;
  }

  const result = XMLValidator.validate(xml);
  return result === true;
}

/**
 * Parse XML with array handling for repeated elements
 * Forces specified tag names to always be arrays, even if only one element exists
 *
 * @param xml - XML string to parse
 * @param arrayTags - Array of tag names that should always be parsed as arrays
 * @returns Parsed JavaScript object with forced arrays
 *
 * @example
 * ```typescript
 * const xml = '<root><item>Test</item></root>';
 * const result = parseXmlWithArrays(xml, ['item']);
 * // Returns: { root: { item: ['Test'] } }
 * // Without arrayTags, would return: { root: { item: 'Test' } }
 * ```
 */
export function parseXmlWithArrays(
  xml: string,
  arrayTags: string[],
  options?: Partial<X2jOptions>
): Record<string, unknown> {
  const mergedOptions: Partial<X2jOptions> = {
    ...DEFAULT_PARSE_OPTIONS,
    ...options,
    isArray: (tagName: string) => arrayTags.includes(tagName),
  };

  const parser = new XMLParser(mergedOptions);
  return parser.parse(xml) as Record<string, unknown>;
}

/**
 * Extract text content from XML, stripping all tags
 *
 * @param xml - XML string
 * @returns Plain text content with tags removed
 *
 * @example
 * ```typescript
 * const xml = '<root><b>Bold</b> and <i>italic</i></root>';
 * const text = extractTextFromXml(xml);
 * // Returns: 'Bold and italic'
 * ```
 */
export function extractTextFromXml(xml: string): string {
  if (!isValidXml(xml)) {
    return '';
  }

  try {
    const parsed = parseXml(xml, { ignoreAttributes: true });
    return extractTextRecursive(parsed).trim();
  } catch {
    return '';
  }
}

/**
 * Recursively extract text from parsed XML object
 * @private
 */
function extractTextRecursive(obj: unknown): string {
  if (typeof obj === 'string' || typeof obj === 'number') {
    return String(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(extractTextRecursive).join(' ');
  }

  if (typeof obj === 'object' && obj !== null) {
    const record = obj as Record<string, unknown>;

    // If object has '#text' property, return it
    if ('#text' in record) {
      return extractTextRecursive(record['#text']);
    }

    // Otherwise, recursively extract from all properties
    return Object.values(record)
      .map(extractTextRecursive)
      .filter(text => text.length > 0)
      .join(' ');
  }

  return '';
}
