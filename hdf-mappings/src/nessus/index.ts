/**
 * Query functions for Nessus to NIST mappings
 */

import type { NessusNistMappings } from './types.js';
import rawMappings from '../data/nessus-nist-mappings.json';

const mappings = rawMappings as NessusNistMappings;

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
  // The mapping data carries numeric plugin IDs alongside the "*" wildcard, so
  // compare on the string form — a strict === against the raw value never
  // matches a scan's (string) plugin ID.
  const exactMatch = mappings.find(
    (m) => m.pluginFamily === pluginFamily && String(m.pluginID) === pluginId
  );
  if (exactMatch) {
    return exactMatch['NIST-ID'];
  }

  // Fall back to wildcard match
  const wildcardMatch = mappings.find(
    (m) => m.pluginFamily === pluginFamily && String(m.pluginID) === '*'
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
  return mappings.filter((m) => m.pluginFamily === pluginFamily);
}

/**
 * Get all plugin families
 * @returns Array of all plugin families
 */
export function getAllNessusPluginFamilies(): string[] {
  const families = new Set(mappings.map((m) => m.pluginFamily));
  return Array.from(families);
}

/**
 * Check if a plugin family exists in the mappings
 * @param pluginFamily - The plugin family to check
 * @returns True if the plugin family exists
 */
export function nessusPluginFamilyExists(pluginFamily: string): boolean {
  return mappings.some((m) => m.pluginFamily === pluginFamily);
}

/**
 * Get all Nessus to NIST mappings
 * @returns Array of all mappings
 */
export function getAllNessusMappings(): NessusNistMappings {
  return [...mappings];
}
