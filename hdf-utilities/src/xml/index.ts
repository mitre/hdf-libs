/**
 * XML parsing utilities for HDF converters
 * Provides XML parsing with sensible defaults for security tool output
 */

import { XMLParser, XMLBuilder, XMLValidator } from 'fast-xml-parser';
import type { X2jOptions, XmlBuilderOptions } from 'fast-xml-parser';

export { findValuesByKey as findXmlValues } from '../object/index.js';

/**
 * Default options for XML parsing optimized for security tool converters.
 *
 * **XXE Safety**: fast-xml-parser v5.x does not process DTD or external entities
 * by default. The `processEntities: false` option is set as defense-in-depth to
 * ensure entity expansion is disabled even if future versions change defaults.
 * See: https://github.com/NaturalIntelligence/fast-xml-parser/blob/master/docs/v5/2.XMLparseOptions.md
 */
const DEFAULT_PARSE_OPTIONS: Partial<X2jOptions> = {
  attributeNamePrefix: '',
  textNodeName: '#text',
  ignoreAttributes: false,
  ignoreDeclaration: true,
  parseAttributeValue: false,
  parseTagValue: false,
  removeNSPrefix: true,
  processEntities: false,
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
  options?: Partial<X2jOptions> & { maxSize?: number }
): Record<string, unknown> {
  if (options?.maxSize !== undefined && xml.length > options.maxSize) {
    throw new Error(
      `Input exceeds maximum allowed size: ${xml.length} bytes exceeds limit of ${options.maxSize} bytes`
    );
  }

  // Validate XML first
  const validation = XMLValidator.validate(xml);
  if (validation !== true) {
    throw new Error(`Invalid XML: ${validation.err.msg}`);
  }

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
 * @param obj - JavaScript object to convert to XML, or a preserveOrder node list.
 *   An array is only meaningful with `preserveOrder: true`; without it the builder
 *   indexes the array and emits elements named by its numeric keys.
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
  obj: Record<string, unknown> | unknown[],
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
/**
 * Whether a character is legal in an XML 1.0 document, per the Char production.
 * The one home for this rule: an emitter deciding what to replace and a
 * validator deciding what to reject must not answer it differently.
 */
export function isXmlChar(ch: string): boolean {
  const c = ch.codePointAt(0) as number;
  return (
    c === 0x9 ||
    c === 0xa ||
    c === 0xd ||
    (c >= 0x20 && c <= 0xd7ff) ||
    (c >= 0xe000 && c <= 0xfffd) ||
    c >= 0x10000
  );
}

/**
 * Replace every character XML 1.0 forbids with U+FFFD, which is what Go's
 * encoding/xml does. XML defines no escape for these — a numeric reference to a
 * C0 control is itself illegal — so the choice is a replacement character or a
 * document no conforming parser will read.
 */
export function xmlSafeText(value: string): string {
  let out = '';
  for (const ch of value) out += isXmlChar(ch) ? ch : '\ufffd';
  return out;
}

export function isValidXml(xml: string): boolean {
  if (!xml || xml.trim().length === 0) {
    return false;
  }

  // The structural validator does not enforce XML 1.0's Char production, so it
  // called a document well-formed that no conforming parser will read — which is
  // how a converter emitting a raw ESC passed its own well-formedness check.
  for (const ch of xml) {
    if (!isXmlChar(ch)) return false;
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
  options?: Partial<X2jOptions> & { maxSize?: number }
): Record<string, unknown> {
  if (options?.maxSize !== undefined && xml.length > options.maxSize) {
    throw new Error(
      `Input exceeds maximum allowed size: ${xml.length} bytes exceeds limit of ${options.maxSize} bytes`
    );
  }

  // Validate XML first (consistency with parseXml)
  const validation = XMLValidator.validate(xml);
  if (validation !== true) {
    throw new Error(`Invalid XML: ${validation.err.msg}`);
  }

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

    // Recursively extract text from all properties
    return Object.values(record)
      .map(extractTextRecursive)
      .filter(text => text.length > 0)
      .join(' ');
  }

  return '';
}

/**
 * Walks the XML prologue — everything before the root element, the only region where a
 * DOCTYPE may legally appear — and reports which declarations it holds.
 *
 * It reports rather than returning the text to search, because the text would still
 * contain commented-out declarations: `<!-- <!DOCTYPE x> -->` is not a declaration, and
 * grepping a region that includes it cannot tell the difference.
 *
 * A fixed byte window cannot bound this region: the prologue may carry any amount of
 * comment and processing-instruction text, so a declaration can be pushed past any
 * constant. Walking to the root element has no such hole, and it is also what stops
 * declaration-shaped CONTENT from false-positiving — once the root is reached, nothing
 * after it is a declaration.
 *
 * An unterminated construct yields no root element, and so no prologue: there is nothing
 * a document that never opens an element can be said to have declared.
 *
 * Kept in parity with Go's scanXMLPrologue by testdata/xml-doctype-cases.json, which
 * both suites read.
 */
export interface XmlPrologueDeclarations {
  /** A DOCTYPE of any kind. A subset of only ELEMENT/ATTLIST/NOTATION is inert. */
  hasDoctype: boolean;
  /** An inline `<!ENTITY>` — the entity-expansion (billion-laughs) vector. */
  hasEntityDecl: boolean;
  /** An external DTD reference (SYSTEM/PUBLIC) — the XXE and SSRF vector. */
  hasExternalId: boolean;
  /**
   * Set when the prologue could not be parsed to a root element, so the other fields are
   * a lower bound rather than a complete answer. A boundary that treats absence of
   * findings as "safe" must refuse this instead.
   */
  malformed: boolean;
}

const isDtdNameChar = (c: string): boolean => /[A-Za-z]/.test(c);
const isSpace = (c: string): boolean => c === ' ' || c === '\t' || c === '\n' || c === '\r';

/**
 * Walks a DTD internal subset from the character after `[`, reporting what it declares
 * plus the offset just past its closing `]>`.
 *
 * A state machine rather than a substring search because the subset's own EXTENT depends
 * on quoting: `<!ATTLIST l v CDATA "]>">` contains a `]>` inside a literal, and a scanner
 * that searches for the first `]>` ends the subset there, loses its place, and reports a
 * document with a later `<!ENTITY>` as clean. Comments hide the same way. Measured: that
 * evasion defeated the substring version of this function.
 */
interface SubsetScan {
  end: number;
  hasEntity: boolean;
  hasExternalId: boolean;
  ok: boolean;
}

function scanInternalSubset(s: string): SubsetScan {
  let hasEntity = false;
  let hasExternalId = false;
  let i = 0;
  const fail = (): SubsetScan => ({ end: 0, hasEntity, hasExternalId, ok: false });
  while (i < s.length) {
    const c = s[i] as string;
    if (c === "'" || c === '"') {
      i++;
      while (i < s.length && s[i] !== c) i++;
      if (i >= s.length) return fail(); // unterminated literal
      i++;
    } else if (s.startsWith('<!--', i)) {
      const closeAt = s.indexOf('-->', i);
      if (closeAt === -1) return fail();
      i = closeAt + 3;
    } else if (s.startsWith('<!', i)) {
      let j = i + 2;
      while (j < s.length && isDtdNameChar(s[j] as string)) j++;
      if (s.slice(i + 2, j).toUpperCase() === 'ENTITY') hasEntity = true;
      i = j;
    } else if (c === ']') {
      let j = i + 1;
      while (j < s.length && isSpace(s[j] as string)) j++;
      if (j < s.length && s[j] === '>') return { end: j + 1, hasEntity, hasExternalId, ok: true };
      i++;
    } else if (s.startsWith('SYSTEM', i) || s.startsWith('PUBLIC', i)) {
      // Only counts outside literals and comments, where it is a keyword rather than
      // text. Conservative: any external reference in the subset counts.
      hasExternalId = true;
      i += 6;
    } else {
      i++;
    }
  }
  return fail(); // subset never closed
}

type PrologueScan = XmlPrologueDeclarations & { foundRoot: boolean };

function scanXmlPrologue(input: string): PrologueScan {
  let hasDoctype = false;
  let hasEntityDecl = false;
  let hasExternalId = false;
  const out = (foundRoot: boolean): PrologueScan => ({
    hasDoctype,
    hasEntityDecl,
    hasExternalId,
    malformed: false,
    foundRoot,
  });
  let i = 0;
  for (;;) {
    while (i < input.length && isSpace(input[i] as string)) i++;
    if (i >= input.length) return out(false);
    const rest = input.slice(i);
    if (rest.startsWith('<?')) {
      const closeAt = rest.indexOf('?>');
      if (closeAt === -1) return out(false);
      i += closeAt + 2;
    } else if (rest.startsWith('<!--')) {
      const closeAt = rest.indexOf('-->');
      if (closeAt === -1) return out(false);
      i += closeAt + 3; // skipped as a unit: its contents declare nothing
    } else if (rest.slice(0, 9).toUpperCase() === '<!DOCTYPE') {
      // Recorded the moment the token is seen, so this fact is sound no matter what the
      // rest of the declaration does. Everything below only ADDS detail.
      hasDoctype = true;
      const open = rest.indexOf('[');
      const gt = rest.indexOf('>');
      if (gt === -1 && open === -1) return out(false);
      if (open !== -1 && (gt === -1 || open < gt)) {
        const head = rest.slice(0, open).toUpperCase();
        if (head.includes('SYSTEM') || head.includes('PUBLIC')) hasExternalId = true;
        const sub = scanInternalSubset(rest.slice(open + 1));
        hasEntityDecl = hasEntityDecl || sub.hasEntity;
        hasExternalId = hasExternalId || sub.hasExternalId;
        if (!sub.ok) return out(false);
        i += open + 1 + sub.end;
      } else {
        const head = rest.slice(0, gt).toUpperCase();
        if (head.includes('SYSTEM') || head.includes('PUBLIC')) hasExternalId = true;
        i += gt + 1;
      }
    } else if (rest.startsWith('<!')) {
      const closeAt = rest.indexOf('>');
      if (closeAt === -1) return out(false);
      i += closeAt + 1;
    } else if (rest.startsWith('<')) {
      return out(true); // the root element
    } else {
      // Character data before any element: not well-formed, nothing to trust.
      return out(false);
    }
  }
}

/**
 * Reports whether the input declares a DOCTYPE before its root element. A DOCTYPE is
 * rejected outright rather than only its inline entities: an external DTD reference needs
 * no `<!ENTITY>` of its own to be an XXE or entity-expansion vector.
 */
export function containsXmlDoctype(input: string): boolean {
  return inspectXmlPrologue(input).hasDoctype;
}

/**
 * Reports what the input's prologue declares. The three facts are separate because they
 * are three different attack surfaces, and which of them a given boundary refuses is a
 * policy decision belonging to that boundary, not here. A document with no root element
 * has no prologue to trust, and reports nothing.
 *
 * Kept in parity with Go's InspectXMLPrologue by testdata/xml-doctype-cases.json.
 */
export function inspectXmlPrologue(input: string): XmlPrologueDeclarations {
  const { hasDoctype, hasEntityDecl, hasExternalId, foundRoot } = scanXmlPrologue(input);
  // Could not reach a root element: report what was seen and set malformed, so a gate
  // can tell "nothing declared" apart from "could not tell" and refuse the second.
  return { hasDoctype, hasEntityDecl, hasExternalId, malformed: !foundRoot };
}

/**
 * Reports whether the input declares an entity before its root element — the
 * billion-laughs shape.
 */
export function containsXmlEntityDeclarations(input: string): boolean {
  return inspectXmlPrologue(input).hasEntityDecl;
}
