/**
 * NIST SP 800-53 control description functions
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { NISTDescriptions } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Lazy-load NIST data
let nistData: NISTDescriptions | null = null;

function loadNISTData(): NISTDescriptions {
  if (nistData === null) {
    const dataPath = join(__dirname, '..', 'data', 'nist-descriptions.json');
    const content = readFileSync(dataPath, 'utf-8');
    nistData = JSON.parse(content) as NISTDescriptions;
  }
  return nistData;
}

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

  const data = loadNISTData();
  return data[nistId];
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
  const data = loadNISTData();
  return Object.keys(data);
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

  const data = loadNISTData();
  return nistId in data;
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
  const data = loadNISTData();
  const familyPrefix = `${family}-`;
  const hasFamily = Object.keys(data).some((key) => key.startsWith(familyPrefix));

  return hasFamily ? family : undefined;
}

// Re-export types
export type { NISTDescriptions } from './types.js';
