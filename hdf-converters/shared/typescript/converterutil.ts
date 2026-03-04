/**
 * Shared utilities for TypeScript HDF converters.
 *
 * Provides common patterns used across all converter implementations:
 * - Input checksum computation
 * - Re-exports of shared constants and utilities
 */

import { sha256 } from '@mitre/hdf-utilities';
import type { Checksum } from '@mitre/hdf-schema';
import { HashAlgorithm } from '@mitre/hdf-schema';
import { getCweNistControl } from '@mitre/hdf-mappings';

/**
 * Compute a SHA-256 checksum of raw converter input.
 *
 * Wraps the common 3-line pattern used in every converter into a single call.
 * The returned Checksum is suitable for the EvaluatedBaseline.resultsChecksum field.
 *
 * @param input - Raw input string (JSON, XML, etc.)
 * @returns Checksum with algorithm set to SHA-256
 */
export async function inputChecksum(input: string): Promise<Checksum> {
  return {
    algorithm: HashAlgorithm.Sha256,
    value: await sha256(input),
  };
}

/**
 * Build a tags object with NIST controls and optional CCI mappings.
 *
 * If cci is empty, the "cci" key is omitted from the result.
 * Additional key-value pairs can be passed via extras.
 *
 * @param nist - NIST 800-53 control identifiers
 * @param cci - CCI identifiers (omitted if empty)
 * @param extras - Additional tag key-value pairs
 * @returns Tags object for HDF requirement
 */
export function buildNistCciTags(
  nist: string[],
  cci: string[],
  extras?: Record<string, unknown>,
): Record<string, unknown> {
  const tags: Record<string, unknown> = { nist };
  if (cci.length > 0) {
    tags.cci = cci;
  }
  if (extras) {
    Object.assign(tags, extras);
  }
  return tags;
}

/** Maximum number of items processed from any single input array. */
export const DEFAULT_MAX_ITEMS = 100_000;

/**
 * Limit an array to at most maxItems elements.
 *
 * Returns the (possibly truncated) array and a flag indicating whether
 * truncation occurred. When truncated, callers should log a warning.
 *
 * @param items - Array to limit
 * @param maxItems - Maximum items (defaults to DEFAULT_MAX_ITEMS)
 * @returns Object with limited items array and truncated flag
 */
export function limitArray<T>(
  items: T[],
  maxItems = DEFAULT_MAX_ITEMS,
): { items: T[]; truncated: boolean } {
  if (items.length <= maxItems) {
    return { items, truncated: false };
  }
  return { items: items.slice(0, maxItems), truncated: true };
}

/**
 * Strip HTML tags from a string, collapsing whitespace.
 *
 * Mirrors the Go shared.StripHTML() in shared/go/converterutil.go.
 *
 * @param html - String potentially containing HTML tags
 * @returns Plain text with tags removed and whitespace normalized
 */
export function stripHTML(html: string): string {
  return html
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Limit an array and log a warning if truncated.
 *
 * Wraps {@link limitArray} with a console.warn call when items are truncated.
 *
 * @param items - Array to limit
 * @param label - Item type label for warning message (e.g., "vulnerability")
 * @param maxItems - Maximum items (defaults to DEFAULT_MAX_ITEMS)
 * @returns Limited array (original if within limit)
 */
export function limitArrayWithWarning<T>(
  items: T[],
  label: string,
  maxItems = DEFAULT_MAX_ITEMS,
): T[] {
  const { items: limited, truncated } = limitArray(items, maxItems);
  if (truncated) {
    // eslint-disable-next-line no-console -- Intentional warning for truncated input
    console.warn(`WARNING: Input truncated at ${limited.length} ${label} items (original: ${items.length})`);
  }
  return limited;
}

/**
 * Map CWE identifiers to NIST 800-53 controls.
 *
 * Looks up each CWE ID, deduplicates, sorts, and falls back to the provided
 * default when no CWE has a mapping. CWE IDs may optionally have a "CWE-"
 * prefix (e.g., "CWE-79" or "79").
 *
 * @param cweIDs - CWE identifiers (e.g., ["CWE-79", "89"])
 * @param fallback - Default NIST controls when no mapping is found
 * @returns Sorted, deduplicated NIST control identifiers
 */
export function mapCWEToNIST(
  cweIDs: string[],
  fallback: string[],
): string[] {
  const controls = new Set<string>();
  for (const id of cweIDs) {
    const numericStr = id.replace(/^CWE-/i, '');
    const numericId = parseInt(numericStr, 10);
    if (!isNaN(numericId)) {
      const nistControl = getCweNistControl(numericId);
      if (nistControl) {
        controls.add(nistControl);
      }
    }
  }
  return controls.size > 0 ? [...controls].sort() : fallback;
}

/** Matches CWE identifiers like "CWE-79", "CWE 89", "cwe22". */
const CWE_PATTERN = /CWE[- ]?(\d+)/gi;

/**
 * Extract all numeric CWE IDs from text.
 * Returns deduplicated sorted array of numeric ID strings (e.g., ["79", "89"]).
 *
 * @param text - Text potentially containing CWE identifiers
 * @returns Sorted, deduplicated numeric CWE ID strings
 */
export function extractCWEIDs(text: string): string[] {
  const matches = [...text.matchAll(CWE_PATTERN)];
  if (matches.length === 0) return [];
  const ids = [...new Set(matches.map(m => m[1]!))];
  ids.sort();
  return ids;
}

/** Default maximum input size for converters (50MB) */
export const DEFAULT_MAX_INPUT_SIZE = 50 * 1024 * 1024;

/**
 * Validates that input string doesn't exceed maximum allowed size.
 *
 * Note: string.length gives char count, not bytes. For multi-byte chars this
 * underestimates. This is acceptable as a coarse safety check — exact byte
 * counting would require TextEncoder.
 *
 * @param input - Raw input string to validate
 * @param converterName - Name of the converter (used in error message)
 * @param maxSize - Maximum allowed character count (defaults to DEFAULT_MAX_INPUT_SIZE)
 * @throws Error if input exceeds maxSize
 */
export function validateInputSize(
  input: string,
  converterName: string,
  maxSize = DEFAULT_MAX_INPUT_SIZE,
): void {
  if (input.length > maxSize) {
    throw new Error(
      `${converterName}: input exceeds maximum allowed size of ${maxSize} characters`,
    );
  }
}

/**
 * Normalise a value that may be a single item, an array, undefined, or null
 * into a guaranteed array.
 *
 * XML-to-JSON parsers often produce a single object when there is one child
 * element and an array when there are multiple. This helper smooths that out.
 *
 * @param value - A single item, an array of items, undefined, or null
 * @returns An array (empty if the input was nullish)
 */
export function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Re-export shared constants for converter convenience
export { DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';

/**
 * Default NIST 800-53 fallback for tools that identify outdated packages or
 * flaws requiring patching (SI-2: Flaw Remediation, RA-5: Vulnerability
 * Monitoring and Scanning).
 *
 * Mirrors Go shared.DefaultRemediationNIST.
 */
export const DEFAULT_REMEDIATION_NIST_TAGS = ['SI-2', 'RA-5'];
