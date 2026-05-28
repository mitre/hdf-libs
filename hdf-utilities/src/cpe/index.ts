/**
 * CPE 2.3 URI parser for HDF converters.
 *
 * Common Platform Enumeration (CPE) 2.3 URIs identify affected products.
 * Container scanners (grype, twistlock, snyk) emit them in vulnerability
 * findings. This module provides an accept-and-warn parser: any input that
 * carries the `cpe:2.3:` prefix is best-effort parsed; deviations from the
 * canonical 13-field form are reported via `warnings` rather than rejected.
 *
 * Canonical form:
 * `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`
 *
 * Reference: NIST IR 7695 (https://csrc.nist.gov/publications/detail/nistir/7695/final)
 */

/** Valid CPE 2.3 `part` values. */
export type CpePart = 'a' | 'o' | 'h' | '*';

/**
 * Parsed CPE 2.3 URI.
 *
 * `warnings` collects any deviations from the canonical form (truncation,
 * extra fields, unknown `part`). An empty array means the input was a strict
 * 13-field, valid-part CPE.
 */
export interface ParsedCpe {
  /** The original input string, unmodified. */
  raw: string;
  /** Application kind. `'a'` (app), `'o'` (OS), `'h'` (hardware), `'*'` (any). */
  part: CpePart | string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  swEdition: string;
  targetSw: string;
  targetHw: string;
  other: string;
  /** Deviation messages; empty when the input is a canonical 13-field CPE. */
  warnings: string[];
}

const CPE_PREFIX = 'cpe:2.3:';
const EXPECTED_TOTAL_FIELDS = 13; // "cpe", "2.3", and 11 product fields = 13 colon-separated tokens
const PRODUCT_FIELD_COUNT = 11; // part + 10 attribute fields
const VALID_PARTS = new Set(['a', 'o', 'h', '*']);

/**
 * Split a CPE 2.3 body on unescaped `:` separators.
 *
 * Per CPE 2.3 spec section 6.1.2.4, `:` and `\` inside a field must be
 * escaped as `\:` and `\\`. We respect those escapes during the split and
 * unescape the result.
 */
function splitOnUnescapedColons(body: string): string[] {
  const result: string[] = [];
  let current = '';
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '\\' && i + 1 < body.length) {
      const next = body[i + 1];
      // Preserve known escapes (\: and \\) as a literal next character.
      if (next === ':' || next === '\\') {
        current += next;
        i++;
        continue;
      }
      // Unknown escape — keep the backslash and continue.
      current += ch;
      continue;
    }
    if (ch === ':') {
      result.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  result.push(current);
  return result;
}

/**
 * Parse a CPE 2.3 URI.
 *
 * Accept-and-warn semantics:
 * - Input missing the `cpe:2.3:` prefix → returns `null`.
 * - Input with the prefix but fewer than 11 product fields → fields are
 *   padded with `"*"` and a `truncated:` warning is added.
 * - Input with more than 11 product fields → extras are dropped and an
 *   `"extra fields ignored"` warning is added.
 * - Unknown `part` value → kept as-is in the result, `"unknown part: X"`
 *   warning is added.
 * - `\:` and `\\` escapes inside fields are honored during splitting and
 *   unescaped in the returned field values.
 *
 * @param cpeUri - CPE 2.3 URI string
 * @returns Parsed CPE with warnings, or `null` if input lacks the prefix
 *
 * @example
 * ```typescript
 * parseCpe('cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*');
 * // { part: 'a', vendor: 'openssl', product: 'openssl', version: '1.1.1k', ... warnings: [] }
 *
 * parseCpe('cpe:2.3:a:openssl:openssl:1.1.1k');
 * // truncated input → padded with '*', warnings: ['truncated: expected 13 colon-separated fields, got 6']
 *
 * parseCpe('openssl:1.1.1k'); // null — no prefix
 * ```
 */
export function parseCpe(cpeUri: string): ParsedCpe | null {
  if (!cpeUri.startsWith(CPE_PREFIX)) {
    return null;
  }

  const warnings: string[] = [];
  const body = cpeUri.slice(CPE_PREFIX.length);

  // Special case: bare prefix `cpe:2.3:` — all fields empty, still warn.
  // This is the "I have nothing useful here" form; padding with "*" would
  // suggest the parser inferred wildcards, which it didn't.
  const isBarePrefix = body.length === 0;

  const bodyParts = isBarePrefix ? [] : splitOnUnescapedColons(body);

  // Total colon-separated fields including the prefix "cpe" and "2.3" markers.
  const totalFields = isBarePrefix ? 2 : 2 + bodyParts.length;

  if (bodyParts.length > PRODUCT_FIELD_COUNT) {
    warnings.push('extra fields ignored');
  } else if (bodyParts.length < PRODUCT_FIELD_COUNT) {
    warnings.push(
      `truncated: expected ${EXPECTED_TOTAL_FIELDS} colon-separated fields, got ${totalFields}`,
    );
  }

  // Pad missing fields. For a bare prefix, pad with "" (no inferred data).
  // For partial input, pad missing trailing fields with "*" (wildcard).
  const padValue = isBarePrefix ? '' : '*';
  const fields: string[] = bodyParts.slice(0, PRODUCT_FIELD_COUNT);
  while (fields.length < PRODUCT_FIELD_COUNT) {
    fields.push(padValue);
  }

  // fields is padded to PRODUCT_FIELD_COUNT above, so every slot is present;
  // the destructuring defaults only satisfy the compiler's indexed-access check.
  const [
    part = '',
    vendor = '',
    product = '',
    version = '',
    update = '',
    edition = '',
    language = '',
    swEdition = '',
    targetSw = '',
    targetHw = '',
    other = '',
  ] = fields;

  if (!VALID_PARTS.has(part)) {
    warnings.push(`unknown part: ${part}`);
  }

  return {
    raw: cpeUri,
    part,
    vendor,
    product,
    version,
    update,
    edition,
    language,
    swEdition,
    targetSw,
    targetHw,
    other,
    warnings,
  };
}
