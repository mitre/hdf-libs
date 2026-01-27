/**
 * Query functions for CWE to NIST mappings
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CweNistMapping, CweNistMappings } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mappings: CweNistMappings | null = null;
let indexById: Map<number, CweNistMapping> | null = null;

function loadMappings(): void {
  if (mappings === null) {
    const dataPath = join(__dirname, '../data/cwe-nist-mappings.json');
    const data = readFileSync(dataPath, 'utf-8');
    mappings = JSON.parse(data) as CweNistMappings;

    // Build index for fast lookups
    indexById = new Map();
    for (const mapping of mappings) {
      indexById.set(mapping['CWE-ID'], mapping);
    }
  }
}

/**
 * Get the full mapping for a CWE ID
 * @param cweId - The CWE ID (number)
 * @returns The mapping object or undefined if not found
 */
export function getCweNistMapping(cweId: number): CweNistMapping | undefined {
  loadMappings();
  return indexById!.get(cweId);
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
  loadMappings();
  return Array.from(indexById!.keys());
}

/**
 * Check if a CWE ID exists in the mappings
 * @param cweId - The CWE ID to check
 * @returns True if the CWE ID exists
 */
export function cweExists(cweId: number): boolean {
  loadMappings();
  return indexById!.has(cweId);
}

/**
 * Get all CWE to NIST mappings
 * @returns Array of all mappings
 */
export function getAllCweMappings(): CweNistMappings {
  loadMappings();
  return [...mappings!];
}
