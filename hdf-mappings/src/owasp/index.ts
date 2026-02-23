/**
 * OWASP Top 10 to NIST mapping functions
 */

import type { OwaspNistMappings, OwaspNistMapping } from './types.js';
import rawOwaspData from '../data/owasp-nist-mappings.json';

const owaspData = rawOwaspData as OwaspNistMappings;
const owaspIndex = new Map<string, OwaspNistMapping>(
  owaspData.map(item => [item['OWASP-ID'], item])
);

/**
 * Get the NIST mapping for an OWASP Top 10 ID.
 *
 * @param owaspId - The OWASP ID (e.g., 'A1', 'A2')
 * @returns The mapping object, or undefined if not found
 *
 * @example
 * ```typescript
 * const mapping = getOwaspNistMapping('A1');
 * // Returns: { 'OWASP-ID': 'A1', 'OWASP Name': 'Injection', 'NIST-ID': 'SI-10', ... }
 * ```
 */
export function getOwaspNistMapping(owaspId: string): OwaspNistMapping | undefined {
  if (!owaspId || typeof owaspId !== 'string') {
    return undefined;
  }

  return owaspIndex.get(owaspId);
}

/**
 * Get the NIST control ID for an OWASP Top 10 ID.
 *
 * @param owaspId - The OWASP ID (e.g., 'A1', 'A2')
 * @returns The NIST control ID, or undefined if not found
 *
 * @example
 * ```typescript
 * const nistId = getOwaspNistControl('A1');
 * // Returns: 'SI-10'
 * ```
 */
export function getOwaspNistControl(owaspId: string): string | undefined {
  const mapping = getOwaspNistMapping(owaspId);
  return mapping?.['NIST-ID'];
}

/**
 * Get the OWASP vulnerability name for an OWASP ID.
 *
 * @param owaspId - The OWASP ID (e.g., 'A1', 'A2')
 * @returns The OWASP vulnerability name, or undefined if not found
 *
 * @example
 * ```typescript
 * const name = getOwaspName('A1');
 * // Returns: 'Injection'
 * ```
 */
export function getOwaspName(owaspId: string): string | undefined {
  const mapping = getOwaspNistMapping(owaspId);
  return mapping?.['OWASP Name'];
}

/**
 * Get all OWASP IDs available in the database.
 *
 * @returns Array of all OWASP IDs
 *
 * @example
 * ```typescript
 * const ids = getAllOwaspIds();
 * // Returns: ['A1', 'A2', 'A3', ..., 'A10']
 * ```
 */
export function getAllOwaspIds(): string[] {
  return Array.from(owaspIndex.keys());
}

/**
 * Check if an OWASP ID exists in the database.
 *
 * @param owaspId - The OWASP ID to check
 * @returns true if the OWASP ID exists, false otherwise
 *
 * @example
 * ```typescript
 * if (owaspExists('A1')) {
 *   console.log('OWASP ID found');
 * }
 * ```
 */
export function owaspExists(owaspId: string): boolean {
  if (!owaspId || typeof owaspId !== 'string') {
    return false;
  }

  return owaspIndex.has(owaspId);
}

/**
 * Get all OWASP to NIST mappings.
 *
 * @returns Array of all mappings
 *
 * @example
 * ```typescript
 * const mappings = getAllOwaspMappings();
 * // Returns all 10 OWASP Top 10 mappings
 * ```
 */
export function getAllOwaspMappings(): OwaspNistMappings {
  return owaspData;
}

// Re-export types
export type { OwaspNistMapping, OwaspNistMappings } from './types.js';
