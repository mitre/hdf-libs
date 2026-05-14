/**
 * XML parsing utilities for HDF converters
 * Provides XML parsing with sensible defaults for security tool output
 *
 * Uses txml for parsing — zero CVEs, zero dependencies, XXE-safe by design
 * (DOCTYPE declarations are skipped entirely; custom entities are never expanded).
 */

import { parse as txmlParse, stringify as txmlStringify, type TNode } from 'txml';

export { findValuesByKey as findXmlValues } from '../object/index.js';

// ---------------------------------------------------------------------------
// Public option types (replaces fast-xml-parser X2jOptions / XmlBuilderOptions)
// ---------------------------------------------------------------------------

/** Options for XML parsing functions */
export interface XmlParseOptions {
  /** Ignore XML attributes (default: false) */
  ignoreAttributes?: boolean;
  /**
   * Prefix prepended to attribute names in the result object.
   * - `''` (default): attributes stored as-is (e.g. `id → obj['id']`).
   * - `'@_'`: attributes stored with prefix (e.g. `id → obj['@_id']`).
   */
  attributeNamePrefix?: string;
  /** Key name used for element text content (default: '#text') */
  textNodeName?: string;
  /**
   * Remove namespace prefixes from element and attribute names (default: true).
   * When true, `ns:tag` → `tag` and `xmlns:ns` declarations are omitted.
   */
  removeNSPrefix?: boolean;
  /** Maximum allowed input size in bytes; throws if exceeded */
  maxSize?: number;
  /**
   * Parse numeric/boolean tag values as typed values.
   * Accepted for API compatibility; txml always returns strings,
   * so this option is recorded but has no effect.
   */
  parseTagValue?: boolean;
  /**
   * Suppress empty nodes in output.
   * Accepted for API compatibility; has no effect on current output.
   */
  suppressEmptyNode?: boolean;
}

/** Options for the XML builder */
export interface XmlBuildOptions {
  /**
   * Prefix that identifies attribute keys in the input object.
   * - `''` (default): primitive-valued keys become XML attributes.
   * - `'@_'`: only keys starting with `@_` become attributes.
   */
  attributeNamePrefix?: string;
  /** Key name used for element text content (default: '#text') */
  textNodeName?: string;
  /** Ignore attributes during building (default: false) */
  ignoreAttributes?: boolean;
  /** Emit newlines and indentation (default: true) */
  format?: boolean;
  /** Indentation string per nesting level (default: '  ') */
  indentBy?: string;
  /** Suppress empty-element closing tags (default: false; has no effect currently) */
  suppressEmptyNode?: boolean;
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const DEFAULT_TEXT_NODE = '#text';
const DEFAULT_INDENT = '  ';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Strip a namespace prefix (`ns:local` → `local`). */
function stripNsPrefix(name: string): string {
  const idx = name.indexOf(':');
  return idx >= 0 ? name.slice(idx + 1) : name;
}

/** Return true for string, number, or boolean values. */
function isPrimitive(v: unknown): v is string | number | boolean {
  const t = typeof v;
  return t === 'string' || t === 'number' || t === 'boolean';
}

/** Escape XML special characters in element text content. */
function escapeXmlText(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Escape XML special characters in attribute values. */
function escapeXmlAttr(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// txml → flat-object conversion (replicates fast-xml-parser output format)
// ---------------------------------------------------------------------------

/**
 * Convert a txml node list to a flat JS object that matches the output format
 * produced by fast-xml-parser with `attributeNamePrefix: ''`.
 *
 * Processing-instruction nodes (`?xml`, `?foo`) and top-level text strings are
 * silently ignored — only real element nodes contribute to the result.
 */
function txmlNodesToObject(
  nodes: (TNode | string)[],
  arrayTags: string[] | null,
  opts: XmlParseOptions,
): Record<string, unknown> {
  const removeNS = opts.removeNSPrefix !== false;

  const elementNodes = nodes.filter(
    (n): n is TNode => typeof n === 'object' && !n.tagName.startsWith('?'),
  );

  const result: Record<string, unknown> = {};
  const groups: Record<string, TNode[]> = {};

  for (const node of elementNodes) {
    const tag = removeNS ? stripNsPrefix(node.tagName) : node.tagName;
    (groups[tag] ??= []).push(node);
  }

  for (const [tag, group] of Object.entries(groups)) {
    const forceArray = arrayTags?.includes(tag) ?? false;
    const values = group.map(n => txmlNodeToValue(n, arrayTags, opts));
    result[tag] = values.length === 1 && !forceArray ? values[0] : values;
  }

  return result;
}

/**
 * Convert a single txml TNode to the JS value that would be produced by
 * fast-xml-parser for that element.
 */
function txmlNodeToValue(
  node: TNode,
  arrayTags: string[] | null,
  opts: XmlParseOptions,
): unknown {
  const textNode = opts.textNodeName ?? DEFAULT_TEXT_NODE;
  const ignoreAttrs = opts.ignoreAttributes ?? false;
  const removeNS = opts.removeNSPrefix !== false;
  const attrPrefix = opts.attributeNamePrefix ?? '';

  // Build effective attribute list; drop xmlns:* declarations when removeNS is true.
  const effectiveAttrs = ignoreAttrs
    ? []
    : Object.entries(node.attributes).filter(([k]) => {
        if (removeNS && (k === 'xmlns' || k.startsWith('xmlns:'))) return false;
        return true;
      });

  const hasAttrs = effectiveAttrs.length > 0;

  const textChildren = node.children.filter((c): c is string => typeof c === 'string');
  const elementChildren = node.children.filter(
    (c): c is TNode => typeof c === 'object' && !c.tagName.startsWith('?'),
  );

  const hasElements = elementChildren.length > 0;
  const textContent = textChildren.join('').trim();
  const hasText = textContent.length > 0;

  // Simple leaf case: no attributes, no child elements — return plain string
  // (empty string '' for empty / self-closing elements, preserving fast-xml-parser behaviour).
  if (!hasAttrs && !hasElements) {
    return textContent;
  }

  // Complex case: build an object for this element.
  const obj: Record<string, unknown> = {};

  for (const [k, v] of effectiveAttrs) {
    const baseName = removeNS ? stripNsPrefix(k) : k;
    obj[`${attrPrefix}${baseName}`] = v ?? '';
  }

  if (hasText) {
    obj[textNode] = textContent;
  }

  if (hasElements) {
    const childObj = txmlNodesToObject(elementChildren, arrayTags, opts);
    Object.assign(obj, childObj);
  }

  return obj;
}

// ---------------------------------------------------------------------------
// XML validation (replaces XMLValidator from fast-xml-parser)
// ---------------------------------------------------------------------------

/**
 * Verify that every opening tag in `xml` has a matching closing tag by scanning
 * the raw string with a state machine that correctly handles:
 *   - Quoted attribute values (prevents false `>` detection inside `attr="a>b"`)
 *   - Self-closing tags (`<tag/>`)
 *   - Processing instructions (`<?...?>`)
 *   - Comments (`<!--...-->`)
 *   - CDATA sections (`<![CDATA[...]]>`)
 *   - DOCTYPE declarations with optional internal subsets (`<!DOCTYPE [...]>`)
 *
 * This check is complementary to `txml.parse()`: txml throws on mismatched closing
 * tags (e.g. `<root><item>Test</root>`) but is lenient about *unclosed* tags
 * (e.g. `<root><item>Test</item>` with no `</root>` does not throw). This function
 * catches both cases by requiring all open tags to be balanced at the end.
 */
function isTagBalanced(xml: string): boolean {
  let open = 0;
  let i = 0;

  while (i < xml.length) {
    if (xml[i] !== '<') {
      i++;
      continue;
    }

    // Processing instruction / XML declaration: <?...?>
    if (xml[i + 1] === '?') {
      const end = xml.indexOf('?>', i + 2);
      i = end === -1 ? xml.length : end + 2;
      continue;
    }

    // Comment: <!--...-->
    if (xml.startsWith('<!--', i)) {
      const end = xml.indexOf('-->', i + 4);
      i = end === -1 ? xml.length : end + 3;
      continue;
    }

    // CDATA section: <![CDATA[...]]>
    if (xml.startsWith('<![CDATA[', i)) {
      const end = xml.indexOf(']]>', i + 9);
      i = end === -1 ? xml.length : end + 3;
      continue;
    }

    // DOCTYPE / other <!…> declarations — handle nested bracket pairs.
    if (xml[i + 1] === '!') {
      i += 2;
      let depth = 0;
      while (i < xml.length) {
        if (xml[i] === '[') depth++;
        else if (xml[i] === ']') depth--;
        else if (xml[i] === '>' && depth <= 0) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    // Closing tag: </tag>
    if (xml[i + 1] === '/') {
      const end = xml.indexOf('>', i + 2);
      if (end === -1) return false;
      open--;
      i = end + 1;
      continue;
    }

    // Opening or self-closing tag — scan past quoted attribute values.
    i++; // skip '<'
    let inQuote = false;
    let quoteChar = '';
    while (i < xml.length) {
      const c = xml[i];
      if (inQuote) {
        if (c === quoteChar) inQuote = false;
      } else if (c === '"' || c === "'") {
        inQuote = true;
        quoteChar = c;
      } else if (c === '>') {
        if (i > 0 && xml[i - 1] !== '/') open++; // self-closing does not increment
        i++;
        break;
      }
      i++;
    }
  }

  return open === 0;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate if a string is well-formed XML.
 *
 * @param xml - String to validate
 * @returns `true` if the string is well-formed XML, `false` otherwise
 *
 * @example
 * ```typescript
 * isValidXml('<root><item>Test</item></root>'); // true
 * isValidXml('<root><item>Test</root>');        // false (mismatched tags)
 * isValidXml('not xml');                        // false
 * ```
 */
export function isValidXml(xml: string): boolean {
  if (!xml || xml.trim().length === 0) {
    return false;
  }

  let nodes: (TNode | string)[];
  try {
    // txml throws on mismatched closing tags
    nodes = txmlParse(xml);
  } catch {
    return false;
  }

  // Must contain at least one real element node (not just text or PIs)
  const hasElement = nodes.some(
    n => typeof n === 'object' && !n.tagName.startsWith('?'),
  );
  if (!hasElement) return false;

  return isTagBalanced(xml);
}

/**
 * Parse XML string to a flat JavaScript object.
 *
 * The output format mirrors fast-xml-parser with these defaults:
 * - Attributes are merged directly into the element object (no prefix).
 * - Text content is stored under the `'#text'` key when mixed with attributes/children.
 * - Namespace prefixes are stripped from both element and attribute names.
 * - Repeated sibling elements become arrays automatically.
 *
 * **XXE Safety**: txml skips DOCTYPE declarations entirely and never expands
 * custom entities, making XXE attacks impossible by design.
 *
 * @param xml - XML string to parse
 * @param options - Optional configuration (merged with defaults)
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
  options?: XmlParseOptions,
): Record<string, unknown> {
  if (options?.maxSize !== undefined && xml.length > options.maxSize) {
    throw new Error(
      `Input exceeds maximum allowed size: ${xml.length} bytes exceeds limit of ${options.maxSize} bytes`,
    );
  }

  let nodes: (TNode | string)[];
  try {
    nodes = txmlParse(xml);
  } catch (err) {
    throw new Error(`Invalid XML: ${(err as Error).message}`);
  }

  const hasElement = nodes.some(
    n => typeof n === 'object' && !n.tagName.startsWith('?'),
  );
  if (!hasElement) {
    throw new Error('Invalid XML: no root element found');
  }

  if (!isTagBalanced(xml)) {
    throw new Error('Invalid XML: unbalanced tags');
  }

  const opts: XmlParseOptions = {
    ignoreAttributes: false,
    textNodeName: DEFAULT_TEXT_NODE,
    removeNSPrefix: true,
    ...options,
  };

  return txmlNodesToObject(nodes, null, opts);
}

/**
 * Build XML string from a JavaScript object.
 *
 * Attribute keys and text-node keys are controlled by `options.attributeNamePrefix`
 * and `options.textNodeName` respectively (see {@link XmlBuildOptions}).
 *
 * @param obj - JavaScript object to convert to XML
 * @param options - Optional builder configuration (merged with defaults)
 * @returns XML string
 *
 * @example
 * ```typescript
 * const obj = { root: { item: { '#text': 'Test' } } };
 * const xml = buildXml(obj);
 * // Returns formatted XML string
 * ```
 */
export function buildXml(
  obj: Record<string, unknown>,
  options?: XmlBuildOptions,
): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(obj)) {
    parts.push(buildNode(key, value, options ?? {}, 0));
  }
  return parts.join('');
}

/** Recursively serialise a key-value pair to an XML element string. */
function buildNode(
  tagName: string,
  value: unknown,
  options: XmlBuildOptions,
  depth: number,
): string {
  const attrPfx = options.attributeNamePrefix ?? '';
  const textNode = options.textNodeName ?? DEFAULT_TEXT_NODE;
  const format = options.format ?? true;
  const indentBy = options.indentBy ?? DEFAULT_INDENT;
  const indent = format ? indentBy.repeat(depth) : '';
  const nl = format ? '\n' : '';

  // Arrays: emit one element per item, no additional wrapping.
  if (Array.isArray(value)) {
    return value.map(item => buildNode(tagName, item, options, depth)).join('');
  }

  // Primitives: element with text content (escaped).
  if (isPrimitive(value)) {
    return `${indent}<${tagName}>${escapeXmlText(String(value))}</${tagName}>${nl}`;
  }

  // null / undefined: empty element.
  if (value === null || value === undefined) {
    return `${indent}<${tagName}></${tagName}>${nl}`;
  }

  // Object: separate into attributes, text content, and child elements.
  const obj = value as Record<string, unknown>;
  const attrParts: string[] = [];
  const childParts: string[] = [];
  let textContent = '';

  for (const [key, val] of Object.entries(obj)) {
    if (key === textNode) {
      textContent = String(val ?? '');
    } else if (attrPfx && key.startsWith(attrPfx)) {
      // Explicit attribute key (e.g. `@_id` with prefix `@_`)
      attrParts.push(` ${key.slice(attrPfx.length)}="${escapeXmlAttr(String(val ?? ''))}"`);
    } else if (!attrPfx && isPrimitive(val)) {
      // Default mode: primitive-valued keys become attributes on the current element.
      attrParts.push(` ${key}="${escapeXmlAttr(String(val))}"`);
    } else if (Array.isArray(val)) {
      for (const item of val) {
        childParts.push(buildNode(key, item, options, depth + 1));
      }
    } else {
      // Object (or non-primitive) → child element.
      childParts.push(buildNode(key, val, options, depth + 1));
    }
  }

  const attrStr = attrParts.join('');
  const hasChildren = childParts.length > 0;
  const hasText = textContent !== '';

  if (!hasChildren && !hasText) {
    return `${indent}<${tagName}${attrStr}></${tagName}>${nl}`;
  }

  if (hasText && !hasChildren) {
    return `${indent}<${tagName}${attrStr}>${escapeXmlText(textContent)}</${tagName}>${nl}`;
  }

  if (format) {
    return `${indent}<${tagName}${attrStr}>\n${childParts.join('')}${indent}</${tagName}>\n`;
  }

  return `<${tagName}${attrStr}>${escapeXmlText(textContent)}${childParts.join('')}</${tagName}>`;
}

/**
 * Parse XML with array handling for repeated elements.
 * Forces specified tag names to always be arrays, even if only one element exists.
 *
 * @param xml - XML string to parse
 * @param arrayTags - Tag names that should always be returned as arrays
 * @param options - Optional configuration (merged with defaults)
 * @returns Parsed JavaScript object with forced arrays
 *
 * @example
 * ```typescript
 * const xml = '<root><item>Test</item></root>';
 * const result = parseXmlWithArrays(xml, ['item']);
 * // Returns: { root: { item: ['Test'] } }
 * // Without arrayTags would return: { root: { item: 'Test' } }
 * ```
 */
export function parseXmlWithArrays(
  xml: string,
  arrayTags: string[],
  options?: XmlParseOptions,
): Record<string, unknown> {
  if (options?.maxSize !== undefined && xml.length > options.maxSize) {
    throw new Error(
      `Input exceeds maximum allowed size: ${xml.length} bytes exceeds limit of ${options.maxSize} bytes`,
    );
  }

  let nodes: (TNode | string)[];
  try {
    nodes = txmlParse(xml);
  } catch (err) {
    throw new Error(`Invalid XML: ${(err as Error).message}`);
  }

  const hasElement = nodes.some(
    n => typeof n === 'object' && !n.tagName.startsWith('?'),
  );
  if (!hasElement) {
    throw new Error('Invalid XML: no root element found');
  }

  if (!isTagBalanced(xml)) {
    throw new Error('Invalid XML: unbalanced tags');
  }

  const opts: XmlParseOptions = {
    ignoreAttributes: false,
    textNodeName: DEFAULT_TEXT_NODE,
    removeNSPrefix: true,
    ...options,
  };

  return txmlNodesToObject(nodes, arrayTags, opts);
}

/**
 * Extract text content from XML, stripping all tags.
 *
 * @param xml - XML string
 * @returns Plain text content with all tags removed, or `''` for invalid XML
 *
 * @example
 * ```typescript
 * const xml = '<root><b>Bold</b> and <i>italic</i></root>';
 * const text = extractTextFromXml(xml);
 * // Returns: 'Bold and italic' (order may vary)
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
 * Recursively extract all text values from a parsed XML object.
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
    return Object.values(record)
      .map(extractTextRecursive)
      .filter(text => text.length > 0)
      .join(' ');
  }

  return '';
}
