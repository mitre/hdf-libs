/**
 * Query functions for CWE to NIST mappings
 */

import type { CweNistMapping, CweNistMappings } from './types.js';
import rawMappings from '../data/cwe-nist-mappings.json';

const mappings = rawMappings as CweNistMappings;
const indexById = new Map<number, CweNistMapping>(
  mappings.map(m => [m['CWE-ID'], m])
);

/**
 * Get the full mapping for a CWE ID
 * @param cweId - The CWE ID (number)
 * @returns The mapping object or undefined if not found
 */
export function getCweNistMapping(cweId: number): CweNistMapping | undefined {
  return indexById.get(cweId);
}

/**
 * Get the NIST control ID for a CWE ID
 * @param cweId - The CWE ID (number)
 * @returns The NIST control ID or undefined if not found
 */
export function getCweNistControl(cweId: number): string | undefined {
  const mapping = getCweNistMapping(cweId);
  return mapping?.['NIST-ID'];
}

/**
 * Get the CWE name for a CWE ID
 * @param cweId - The CWE ID (number)
 * @returns The CWE name or undefined if not found
 */
export function getCweName(cweId: number): string | undefined {
  const mapping = getCweNistMapping(cweId);
  return mapping?.['CWE Name'];
}

/**
 * Get all CWE IDs
 * @returns Array of all CWE IDs
 */
export function getAllCweIds(): number[] {
  return Array.from(indexById.keys());
}

/**
 * Check if a CWE ID exists in the mappings
 * @param cweId - The CWE ID to check
 * @returns True if the CWE ID exists
 */
export function cweExists(cweId: number): boolean {
  return indexById.has(cweId);
}

/**
 * Get all CWE to NIST mappings
 * @returns Array of all mappings
 */
export function getAllCweMappings(): CweNistMappings {
  return [...mappings];
}
