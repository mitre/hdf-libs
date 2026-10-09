/**
 * CWE identifier extraction — the TypeScript twin of hdf-utilities/go/cwe.go.
 *
 * It lives here rather than in hdf-converters because it is schema-free string
 * handling, and because the Go original has always been in this package: the
 * engine's cwe filter can reach hdf-utilities and cannot reach hdf-converters.
 */

/** Matches CWE identifiers like "CWE-79", "CWE 79", "cwe79". */
export const CWE_PATTERN = /CWE[- ]?(\d+)/gi;

/**
 * Extracts every numeric CWE ID from a string, deduplicated and sorted — e.g.
 * "CWE-79 and cwe89" yields ["79", "89"]. Returns an empty array when the text
 * names none. Parity: ExtractCWEIDs in go/cwe.go.
 */
export function extractCWEIDs(text: string): string[] {
  const matches = [...text.matchAll(CWE_PATTERN)];
  if (matches.length === 0) return [];
  const ids = [...new Set(matches.map((m) => m[1]!))];
  ids.sort();
  return ids;
}
