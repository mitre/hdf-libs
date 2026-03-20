/**
 * Shared XML utilities for fingerprint detection.
 *
 * Extracts root element name from XML strings, handling declarations,
 * comments, DOCTYPE (including internal subsets), and namespace prefixes.
 */

/**
 * Extract the root element local name from an XML string.
 * Skips XML declarations (<?...?>), comments (<!--...-->),
 * and DOCTYPE declarations (<!DOCTYPE ... [...]>).
 * Strips namespace prefixes (e.g., xccdf:Benchmark -> Benchmark).
 *
 * Returns null if no element found.
 */
export function extractXmlRootElement(input: string): string | null {
  let s = input;
  while (true) {
    s = s.trimStart();
    if (s.startsWith('<?')) {
      // XML processing instruction: <?...?>
      const end = s.indexOf('?>');
      if (end === -1) return null;
      s = s.slice(end + 2);
    } else if (s.startsWith('<!--')) {
      // XML comment: <!--...-->
      const end = s.indexOf('-->');
      if (end === -1) return null;
      s = s.slice(end + 3);
    } else if (s.startsWith('<!DOCTYPE') || s.startsWith('<!doctype')) {
      // DOCTYPE: may have internal subset in [...]
      const bracket = s.indexOf('[');
      const gt = s.indexOf('>');
      if (gt === -1) return null;
      if (bracket !== -1 && bracket < gt) {
        // Has internal subset: skip to ]>
        const endSubset = s.indexOf(']>');
        if (endSubset === -1) return null;
        s = s.slice(endSubset + 2);
      } else {
        // Simple DOCTYPE without internal subset
        s = s.slice(gt + 1);
      }
    } else if (s.startsWith('<!')) {
      // Other markup declaration
      const end = s.indexOf('>');
      if (end === -1) return null;
      s = s.slice(end + 1);
    } else {
      break;
    }
  }
  // Match the root element, stripping optional namespace prefix
  const m = s.match(/^<(?:[a-zA-Z_][\w.-]*:)?([a-zA-Z_][\w.-]*)/);
  return m?.[1] ?? null;
}
