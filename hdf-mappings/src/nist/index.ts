/**
 * NIST SP 800-53 control description functions
 */

import type { NISTDescriptions } from './types.js';
import rawNistData from '../data/nist-descriptions.json';

const nistData = rawNistData as NISTDescriptions;

/**
 * Get the description for a NIST control ID.
 *
 * @param nistId - The NIST control ID (e.g., 'AC-01', 'AC-01 a', 'AC-01 a 01')
 * @returns The NIST control description, or undefined if not found
 *
 * @example
 * ```typescript
 * const desc = getNISTDescription('AC-01');
 * // Returns: "ACCESS CONTROL POLICY AND PROCEDURES"
 * ```
 */
export function getNISTDescription(nistId: string): string | undefined {
  if (!nistId || typeof nistId !== 'string') {
    return undefined;
  }

  return nistData[nistId];
}

/**
 * Get all NIST control IDs available in the database.
 *
 * @returns Array of all NIST control IDs
 *
 * @example
 * ```typescript
 * const ids = getAllNISTIds();
 * // Returns: ['AC-01', 'AC-01 a', 'AC-02', ...]
 * ```
 */
export function getAllNISTIds(): string[] {
  return Object.keys(nistData);
}

/**
 * Check if a NIST control ID exists in the database.
 *
 * @param nistId - The NIST control ID to check
 * @returns true if the NIST control exists, false otherwise
 *
 * @example
 * ```typescript
 * if (nistExists('AC-01')) {
 *   console.log('NIST control found');
 * }
 * ```
 */
export function nistExists(nistId: string): boolean {
  if (!nistId || typeof nistId !== 'string') {
    return false;
  }

  return nistId in nistData;
}

/**
 * Extract the NIST family from a NIST control ID.
 *
 * @param nistId - The NIST control ID (e.g., 'AC-01', 'AC-01 a')
 * @returns The NIST family code (e.g., 'AC'), or undefined if invalid
 *
 * @example
 * ```typescript
 * const family = getNISTFamily('AC-01');
 * // Returns: 'AC'
 *
 * const family2 = getNISTFamily('AC-01 a 01');
 * // Returns: 'AC'
 * ```
 */
export function getNISTFamily(nistId: string): string | undefined {
  if (!nistId || typeof nistId !== 'string') {
    return undefined;
  }

  // Extract family from format like "AC-01" or "AC-01 a"
  const match = nistId.match(/^([A-Z]{2})-/);
  if (!match) {
    return undefined;
  }

  const family = match[1];

  // Validate that this family exists in our database by checking
  // if any controls start with this family
  const familyPrefix = `${family}-`;
  const hasFamily = Object.keys(nistData).some((key) => key.startsWith(familyPrefix));

  return hasFamily ? family : undefined;
}

/**
 * Canonical NIST 800-53 fallback tags for converters when a finding has no
 * CWE or the CWE has no NIST mapping. Categories match heimdall2's global.ts.
 *
 * - SA-11: Developer Security Testing and Evaluation
 * - RA-5: Vulnerability Monitoring and Scanning
 * - SI-2: Flaw Remediation
 * - CM-8: System Component Inventory
 */

/** Static analysis and vulnerability scanning tools (SA-11 + RA-5). */
export const DEFAULT_STATIC_ANALYSIS_NIST_TAGS: string[] = ['SA-11', 'RA-5'];

/** Tools that identify outdated packages or flaws requiring patching (SI-2 + RA-5). */
export const DEFAULT_REMEDIATION_NIST_TAGS: string[] = ['SI-2', 'RA-5'];

/** Dependency/inventory management tools (CM-8). */
export const DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS: string[] = ['CM-8'];

// Re-export types
export type { NISTDescriptions } from './types.js';
