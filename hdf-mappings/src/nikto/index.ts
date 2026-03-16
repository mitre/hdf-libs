/**
 * Query functions for Nikto to NIST mappings
 */

import type { NiktoNistMappings } from './types.js';
import rawMappings from '../data/nikto-nist-mappings.json';

const mappings = rawMappings as NiktoNistMappings;

/**
 * Get the NIST control ID for a Nikto test ID
 * @param niktoId - The Nikto test ID (string or number)
 * @returns The NIST control ID or undefined if not found
 */
export function getNiktoNistControl(niktoId: string | number): string | undefined {
  const id = typeof niktoId === 'number' ? niktoId.toString() : niktoId;
  return mappings[id];
}

/**
 * Get all Nikto test IDs
 * @returns Array of all Nikto test IDs
 */
export function getAllNiktoIds(): string[] {
  return Object.keys(mappings);
}

/**
 * Check if a Nikto test ID exists in the mappings
 * @param niktoId - The Nikto test ID to check
 * @returns True if the Nikto test ID exists
 */
export function niktoExists(niktoId: string | number): boolean {
  const id = typeof niktoId === 'number' ? niktoId.toString() : niktoId;
  return id in mappings;
}

/**
 * Get all Nikto to NIST mappings
 * @returns Object mapping Nikto test IDs to NIST control IDs
 */
export function getAllNiktoMappings(): NiktoNistMappings {
  return { ...mappings };
}
