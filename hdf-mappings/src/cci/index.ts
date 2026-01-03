/**
 * CCI (Control Correlation Identifier) mapping functions
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { CCIMappings } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Lazy-load CCI data
let cciData: CCIMappings | null = null;

function loadCCIData(): CCIMappings {
  if (cciData === null) {
    const dataPath = join(__dirname, '..', 'data', 'cci-mappings.json');
    const content = readFileSync(dataPath, 'utf-8');
    cciData = JSON.parse(content) as CCIMappings;
  }
  return cciData;
}

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

  const data = loadCCIData();
  const item = data[cciId];
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

  const data = loadCCIData();
  const item = data[cciId];
  return item?.nist;
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
  const data = loadCCIData();
  return Object.keys(data);
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

  const data = loadCCIData();
  return cciId in data;
}

// Re-export types
export type { CCIItem, CCIMappings } from './types.js';
