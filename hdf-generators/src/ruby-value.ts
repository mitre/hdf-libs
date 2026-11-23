import { escapeQuotes } from './ruby-escape.js';

/** A key Ruby accepts as a bare hash label ("key: value"). */
const RUBY_LABEL = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Orders strings by code point, as Go's sort.Strings orders UTF-8 bytes, so
 * both generators write tags and hash keys in the same order.
 */
export function byCodePoint(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/**
 * Writes a JSON-shaped value as a Ruby literal: nil, true/false, a number as
 * JavaScript prints it, a string through escapeQuotes, an array, or a hash with
 * string keys in sorted order. Mirrors the Go rubyValue.
 */
export function rubyValue(value: unknown): string {
  if (value === null || value === undefined) return 'nil';
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') return rubyNumber(value);
  if (typeof value === 'string') return escapeQuotes(value);
  if (Array.isArray(value)) return `[${value.map(rubyValue).join(', ')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => byCodePoint(a, b));
    if (entries.length === 0) return '{}';
    return `{ ${entries.map(([k, v]) => `${escapeQuotes(k)} => ${rubyValue(v)}`).join(', ')} }`;
  }
  return escapeQuotes(String(value));
}

/**
 * A number as JavaScript prints it; NaN and infinity, which JSON cannot carry,
 * are Ruby's Float constants. Mirrors the Go jsNumber.
 */
function rubyNumber(n: number): string {
  if (Number.isNaN(n)) return 'Float::NAN';
  if (n === Number.POSITIVE_INFINITY) return 'Float::INFINITY';
  if (n === Number.NEGATIVE_INFINITY) return '-Float::INFINITY';
  return String(n);
}

/**
 * Formats a single tag key-value pair as Ruby DSL whose key and value InSpec
 * reads back unchanged. Parity: formatTag (Go), pinned by
 * testdata/ruby-tag-cases.json.
 */
export function formatTag(key: string, value: unknown): string {
  const v = rubyValue(value);
  if (RUBY_LABEL.test(key)) return `tag ${key}: ${v}`;
  const lit = escapeQuotes(key);
  return lit.startsWith('%q(') ? `tag ${lit} => ${v}` : `tag ${lit}: ${v}`;
}
