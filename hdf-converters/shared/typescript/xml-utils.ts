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
  // Skip past XML declaration, DOCTYPE, and comments to find first real element
  const rootMatch = input.match(
    /<(?:\?[^?]*\?>[\s]*)*(?:![^>]*>[\s]*)*<(?:[a-zA-Z_][\w.-]*:)?([a-zA-Z_][\w.-]*)/
  );
  return rootMatch ? rootMatch[1] : null;
}
