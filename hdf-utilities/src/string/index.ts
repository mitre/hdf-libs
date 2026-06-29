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

// A bare ISO-8601 datetime with a time component but no timezone designator.
// JavaScript's Date constructor interprets such a value as host-LOCAL time,
// whereas Go's time.Parse (and HDF's canonical model) treats it as UTC. We
// append 'Z' to force UTC so output is host-timezone-independent.
const ISO_DATETIME_NO_ZONE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?$/;

// C ctime layout ("Tue Mar 22 14:54:47 2022", or "Mon Jan  2 ..." for a
// single-digit day). Go's hdfutil.ParseTimestamp parses this layout as UTC;
// V8's Date treats it as host-local, so we append a 'GMT' designator to match.
const CTIME_NO_ZONE = /^[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/;

/**
 * Parse a timestamp string in various common formats into a Date.
 *
 * A zone-less ISO datetime (e.g. `2024-01-15T10:30:00`) is interpreted as
 * UTC — matching Go's `hdfutil.ParseTimestamp` — rather than host-local time,
 * so converter output does not depend on the machine's timezone.
 *
 * Returns `null` if the input is empty or cannot be parsed.
 *
 * @param s - Timestamp string to parse
 * @returns Parsed Date or null if unparseable
 *
 * @example
 * ```typescript
 * parseTimestamp('2024-01-15T10:30:00Z'); // Date object
 * parseTimestamp('2024-01-15T10:30:00');  // Date object (interpreted as UTC)
 * parseTimestamp('not a date'); // null
 * parseTimestamp(''); // null
 * ```
 */
export function parseTimestamp(s: string): Date | null {
  if (!s || s.trim().length === 0) {
    return null;
  }

  const trimmed = s.trim();
  let normalized = trimmed;
  if (ISO_DATETIME_NO_ZONE.test(trimmed)) {
    normalized = `${trimmed.replace(' ', 'T')}Z`;
  } else if (CTIME_NO_ZONE.test(trimmed)) {
    normalized = `${trimmed} GMT`;
  }

  const parsed = new Date(normalized);
  if (isNaN(parsed.getTime())) {
    return null;
  }

  return parsed;
}

/**
 * Trim trailing fractional-second zeros from an RFC3339 UTC timestamp string,
 * matching Go's RFC3339Nano marshaling (which drops trailing zeros and the
 * decimal point when the fraction is all zeros).
 *
 * @example
 *   trimUtcFraction('2024-11-15T10:30:00.000Z'); // '2024-11-15T10:30:00Z'
 *   trimUtcFraction('2024-01-01T00:00:00.120Z'); // '2024-01-01T00:00:00.12Z'
 */
export function trimUtcFraction(s: string): string {
  return s.replace(/\.(\d*?)0+Z$/, (_m, keep: string) => (keep ? `.${keep}Z` : 'Z'));
}

/**
 * Format a Date as HDF's canonical timestamp: RFC3339 in UTC with trailing
 * fractional-second zeros trimmed. Byte-identical to what the Go converters
 * emit for the same instant (a UTC `time.Time` marshaled as RFC3339Nano).
 *
 * @example
 *   formatTimestamp(new Date('2024-11-15T10:30:00Z')); // '2024-11-15T10:30:00Z'
 */
export function formatTimestamp(d: Date): string {
  return trimUtcFraction(d.toISOString());
}

/**
 * Format a Date as RFC3339 in UTC truncated to whole seconds (no fractional
 * part). For exporters whose target format conventionally uses whole-second
 * timestamps (CSAF, OpenVEX, CycloneDX). Use {@link formatTimestamp} for
 * canonical HDF output instead — it preserves sub-second precision.
 *
 * @example
 *   formatTimestampSeconds(new Date('2024-11-15T10:30:00.123Z')); // '2024-11-15T10:30:00Z'
 */
export function formatTimestampSeconds(d: Date): string {
  return d.toISOString().replace(/\.\d+Z$/, 'Z');
}
