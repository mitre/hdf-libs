// Glob matching — the TypeScript peer of hdf-engine/go/safematch.go. Kept at
// behavioural parity with the Go matcher.

const MAX_PATTERN_LENGTH = 256;

const REGEX_SPECIAL = new Set(['.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\']);

/**
 * globToRegex converts a glob pattern (with * and ? wildcards) to an anchored
 * regular expression, escaping every other regex metacharacter exactly once. A
 * single pass avoids re-escaping the backslash introduced by escaping an earlier
 * metacharacter (the doubled-backslash defect that made any dotted pattern match
 * nothing).
 */
export function globToRegex(glob: string): string {
  let result = '^';
  for (const ch of glob) {
    if (ch === '*') {
      result += '.*';
    } else if (ch === '?') {
      result += '.';
    } else if (REGEX_SPECIAL.has(ch)) {
      result += '\\' + ch;
    } else {
      result += ch;
    }
  }
  return result + '$';
}

/**
 * safeGlobMatch converts a glob pattern to a regex and matches case-insensitively.
 * Returns false for over-length or invalid patterns (fail-safe), mirroring the
 * Go matcher's length cap and error handling.
 */
const byteEncoder = new TextEncoder();

/** byteLength returns the UTF-8 byte length, matching Go's len(string). */
function byteLength(s: string): number {
  return byteEncoder.encode(s).length;
}

export function safeGlobMatch(s: string, pattern: string): boolean {
  // Cap on UTF-8 byte length (matching Go's len(pattern)), and — like Go's
  // compileSafeRegex — re-cap the EXPANDED regex, so an over-length glob or a
  // small glob that expands past the limit is rejected identically in both
  // languages (not just capped on the raw glob's UTF-16 length).
  if (byteLength(pattern) > MAX_PATTERN_LENGTH) {
    return false;
  }
  const rx = globToRegex(pattern);
  if (byteLength(rx) > MAX_PATTERN_LENGTH) {
    return false;
  }
  let re: RegExp;
  try {
    re = new RegExp(rx, 'i');
  } catch {
    return false;
  }
  return re.test(s);
}
