// Glob matching — the TypeScript peer of hdf-engine/go/safematch.go. Kept at
// behavioural parity, including the doubled-backslash quirk of globToRegex.

const MAX_PATTERN_LENGTH = 256;

/**
 * globToRegex converts a glob pattern (with * and ? wildcards) to an anchored
 * regular expression, escaping all other regex metacharacters. Note: because
 * the backslash is escaped last, the backslash added when escaping '.' is itself
 * doubled — this matches the Go implementation exactly and is preserved verbatim.
 */
export function globToRegex(glob: string): string {
  const special = ['.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\'];
  let result = glob;
  for (const s of special) {
    result = result.split(s).join('\\' + s);
  }
  result = result.split('*').join('.*');
  result = result.split('?').join('.');
  return '^' + result + '$';
}

/**
 * safeGlobMatch converts a glob pattern to a regex and matches case-insensitively.
 * Returns false for over-length or invalid patterns (fail-safe), mirroring the
 * Go matcher's length cap and error handling.
 */
export function safeGlobMatch(s: string, pattern: string): boolean {
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return false;
  }
  let re: RegExp;
  try {
    re = new RegExp(globToRegex(pattern), 'i');
  } catch {
    return false;
  }
  return re.test(s);
}
