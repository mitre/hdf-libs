/**
 * CCI (Control Correlation Identifier) mapping functions
 */

import type { CCIMappings, NistCCIMappings } from './types.js';
import rawCCIData from '../data/cci-mappings.json';
import rawNistCCIData from '../data/nist-cci-mappings.json';
import { getCurrentNistRevision, nistControlsAtRevision } from '../nist/index.js';

// The DISA CCI list's NIST references are Rev 4-era (they include Appendix J
// privacy controls and SA-12/SA-19, all withdrawn or relocated in Rev 5).
// getCCINistMappings translates to the current module-global revision.
const NATIVE_REVISION = 4;

const cciData = rawCCIData as CCIMappings;
const nistCCIData = rawNistCCIData as NistCCIMappings;

/**
 * Get the definition/description for a CCI ID.
 *
 * @param cciId - The CCI ID (e.g., 'CCI-000001')
 * @returns The CCI definition, or undefined if not found
 *
 * @example
 * ```typescript
 * const def = getCCIDescription('CCI-000001');
 * // Returns: "The organization develops an access control policy..."
 * ```
 */
export function getCCIDescription(cciId: string): string | undefined {
  if (!cciId || typeof cciId !== 'string') {
    return undefined;
  }

  const item = cciData[cciId];
  return item?.def;
}

/**
 * Get the NIST control mappings for a CCI ID.
 *
 * @param cciId - The CCI ID (e.g., 'CCI-000001')
 * @returns Array of NIST control references, or undefined if not found
 *
 * @example
 * ```typescript
 * const mappings = getCCINistMappings('CCI-000001');
 * // Returns: ['AC-1 a', 'AC-1.1 (i and ii)', 'AC-1 a 1']
 * ```
 */
export function getCCINistMappings(cciId: string): string[] | undefined {
  if (!cciId || typeof cciId !== 'string') {
    return undefined;
  }

  const item = cciData[cciId];
  if (!item) return undefined;
  return nistControlsAtRevision(item.nist, NATIVE_REVISION, getCurrentNistRevision());
}

/**
 * Get all CCI IDs available in the database.
 *
 * @returns Array of all CCI IDs
 *
 * @example
 * ```typescript
 * const ids = getAllCCIIds();
 * // Returns: ['CCI-000001', 'CCI-000002', ...]
 * ```
 */
export function getAllCCIIds(): string[] {
  return Object.keys(cciData);
}

/**
 * Check if a CCI ID exists in the database.
 *
 * @param cciId - The CCI ID to check
 * @returns true if the CCI exists, false otherwise
 *
 * @example
 * ```typescript
 * if (cciExists('CCI-000001')) {
 *   console.log('CCI found');
 * }
 * ```
 */
export function cciExists(cciId: string): boolean {
  if (!cciId || typeof cciId !== 'string') {
    return false;
  }

  return cciId in cciData;
}

/**
 * Extract the base NIST control identifier from a potentially qualified string.
 * For example, "SI-10 a 1" → "SI-10", "AC-3 (2)" → "AC-3".
 */
function baseNistControl(control: string): string {
  const idx = control.search(/[ (.]/);
  return idx === -1 ? control : control.slice(0, idx);
}

/**
 * Get CCI IDs for a NIST control using the curated mapping table.
 * The input is normalized to its base control before lookup.
 *
 * @param nistControl - NIST control string (e.g., 'SI-10', 'AC-3 (2)')
 * @returns Array of CCI IDs, or undefined if not found
 *
 * @example
 * ```typescript
 * const ccis = getNistCCIMappings('SI-10');
 * // Returns: ['CCI-001310']
 * ```
 */
export function getNistCCIMappings(nistControl: string): string[] | undefined {
  if (!nistControl || typeof nistControl !== 'string') {
    return undefined;
  }
  const base = baseNistControl(nistControl);
  return nistCCIData[base];
}

/**
 * Map NIST 800-53 controls to their CCI IDs using the curated mapping table.
 * Results are deduplicated and sorted.
 *
 * @param nistControls - Array of NIST control strings
 * @returns Deduplicated, sorted array of CCI IDs (empty array if no mappings found)
 *
 * @example
 * ```typescript
 * const ccis = nistToCci(['AC-3', 'SI-10']);
 * // Returns: ['CCI-000213', 'CCI-001310']
 * ```
 */
export function nistToCci(nistControls: string[]): string[] {
  const seen = new Set<string>();
  for (const control of nistControls) {
    const ccis = getNistCCIMappings(control);
    if (ccis) {
      for (const cciId of ccis) {
        seen.add(cciId);
      }
    }
  }
  return Array.from(seen).sort();
}

// Re-export types
export type { CCIItem, CCIMappings, NistCCIMappings } from './types.js';
