/**
 * Shared XML utilities for fingerprint detection.
 *
 * Extracts root element name from XML strings, handling declarations,
 * comments, and namespace prefixes.
 */

/**
 * Extract the root element local name from an XML string.
 * Skips XML declarations (<?...?>), comments (<!--...-->),
 * and DOCTYPE declarations (<!DOCTYPE ...>).
 * Strips namespace prefixes (e.g., xccdf:Benchmark -> Benchmark).
 *
 * Returns null if no element found.
 */
export function extractXmlRootElement(input: string): string | null {
  // Strip leading whitespace, XML declarations (<?...?>), DOCTYPEs (<!...>), and comments (<!--...-->)
  let s = input;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    s = s.trimStart();
    if (s.startsWith('<?')) {
      const end = s.indexOf('?>');
      if (end === -1) return null;
      s = s.slice(end + 2);
    } else if (s.startsWith('<!--')) {
      const end = s.indexOf('-->');
      if (end === -1) return null;
      s = s.slice(end + 3);
    } else if (s.startsWith('<!')) {
      const end = s.indexOf('>');
      if (end === -1) return null;
      s = s.slice(end + 1);
    } else {
      break;
    }
  }
  // Now s should start with the root element tag (or not be XML at all)
  const m = s.match(/^<(?:[a-zA-Z_][\w.-]*:)?([a-zA-Z_][\w.-]*)/);
  return m ? m[1] : null;
}
