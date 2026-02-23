/**
 * String manipulation utilities for HDF converters.
 *
 * These handle common operations on security tool output strings:
 * HTML stripping for STIG descriptions and SonarQube messages,
 * and multi-format timestamp parsing for tool output dates.
 */

/**
 * Remove HTML tags from a string and normalize whitespace.
 *
 * Strips all HTML/XML tags, collapses multiple whitespace characters
 * into single spaces, and trims leading/trailing whitespace.
 *
 * For XML documents, use {@link extractTextFromXml} from the xml module instead.
 * This function is for inline HTML in non-XML strings (STIG descriptions,
 * SonarQube messages, etc.).
 *
 * @param html - String potentially containing HTML tags
 * @returns Plain text with tags removed and whitespace normalized
 *
 * @example
 * ```typescript
 * stripHtml('<p>hello</p> <b>world</b>'); // 'hello world'
 * stripHtml('no tags here'); // 'no tags here'
 * ```
 */
export function stripHtml(html: string): string {
  const stripped = html.replace(/<[^>]*>/g, ' ');
  return stripped.replace(/\s+/g, ' ').trim();
}

/**
 * Parse a timestamp string in various common formats.
 *
 * Attempts to parse the input using the JavaScript Date constructor, which
 * supports ISO 8601, RFC 2822, and several other formats natively.
 *
 * Returns `null` if the input is empty or cannot be parsed.
 *
 * Equivalent to the Go `ParseTimestamp` in shared/go/converterutil.go.
 *
 * @param s - Timestamp string to parse
 * @returns Parsed Date or null if unparseable
 *
 * @example
 * ```typescript
 * parseTimestamp('2024-01-15T10:30:00Z'); // Date object
 * parseTimestamp('Mon, 15 Jan 2024 10:30:00 UTC'); // Date object
 * parseTimestamp('not a date'); // null
 * parseTimestamp(''); // null
 * ```
 */
export function parseTimestamp(s: string): Date | null {
  if (!s || s.trim().length === 0) {
    return null;
  }

  const parsed = new Date(s);
  if (isNaN(parsed.getTime())) {
    return null;
  }

  return parsed;
}
