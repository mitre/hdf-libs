/**
 * Escape a string for use as a Ruby string literal.
 *
 * Strategy:
 * - If the string contains both single and double quotes → %q() wrapper
 * - If the string contains only single quotes → double-quoted with escaping
 * - Otherwise → single-quoted with escaping
 *
 * Ported from ts-inspec-objects escapeQuotes(), cross-referenced with
 * inspec-parser's RubyRebuilder.
 */
export function escapeQuotes(s: string): string {
  const hasSingle = s.includes("'");
  const hasDouble = s.includes('"');

  if (hasSingle && hasDouble) {
    // %q() — escape backslashes before ) so Ruby doesn't treat \) as escaped delimiter
    return `%q(${s.replace(/\\\)/g, '\\\\)')})`;
  }

  if (hasSingle) {
    // Double-quoted: escape backslashes, then double quotes
    return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }

  // Single-quoted: escape backslashes, then single quotes
  return `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}
