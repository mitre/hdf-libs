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

// Re-export shared constants for converter convenience
export { DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';
