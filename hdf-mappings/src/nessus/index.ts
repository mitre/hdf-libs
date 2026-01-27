/**
 * Query functions for Nessus to NIST mappings
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { NessusNistMapping, NessusNistMappings } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mappings: NessusNistMappings | null = null;

function loadMappings(): void {
  if (mappings === null) {
    const dataPath = join(__dirname, '../data/nessus-nist-mappings.json');
    const data = readFileSync(dataPath, 'utf-8');
    mappings = JSON.parse(data) as NessusNistMappings;
  }
}

/**
 * Get the NIST control ID for a Nessus plugin family and plugin ID
 * @param pluginFamily - The Nessus plugin family
 * @param pluginId - The Nessus plugin ID (optional, defaults to "*")
 * @returns The NIST control ID or undefined if not found
 */
export function getNessusNistControl(
  pluginFamily: string,
  pluginId = '*'
): string | undefined {
  loadMappings();

  // First try exact match with plugin ID
  const exactMatch = mappings!.find(
    (m) => m.pluginFamily === pluginFamily && m.pluginID === pluginId
  );
  if (exactMatch) {
    return exactMatch['NIST-ID'];
  }

  // Fall back to wildcard match
  const wildcardMatch = mappings!.find(
    (m) => m.pluginFamily === pluginFamily && m.pluginID === '*'
  );
  return wildcardMatch?.['NIST-ID'];
}

/**
 * Get all mappings for a plugin family
 * @param pluginFamily - The Nessus plugin family
 * @returns Array of mappings for the plugin family
 */
export function getNessusPluginFamilyMappings(
  pluginFamily: string
): NessusNistMappings {
  loadMappings();
  return mappings!.filter((m) => m.pluginFamily === pluginFamily);
}

/**
 * Get all plugin families
 * @returns Array of all plugin families
 */
export function getAllNessusPluginFamilies(): string[] {
  loadMappings();
  const families = new Set(mappings!.map((m) => m.pluginFamily));
  return Array.from(families);
}

/**
 * Check if a plugin family exists in the mappings
 * @param pluginFamily - The plugin family to check
 * @returns True if the plugin family exists
 */
export function nessusPluginFamilyExists(pluginFamily: string): boolean {
  loadMappings();
  return mappings!.some((m) => m.pluginFamily === pluginFamily);
}

/**
 * Get all Nessus to NIST mappings
 * @returns Array of all mappings
 */
export function getAllNessusMappings(): NessusNistMappings {
  loadMappings();
  return [...mappings!];
}
