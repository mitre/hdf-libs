/**
 * Query functions for ScoutSuite to NIST mappings
 */

import type { ScoutsuiteNistMapping, ScoutsuiteNistMappings } from './types.js';
import rawMappings from '../data/scoutsuite-nist-mappings.json';

const mappings = rawMappings as ScoutsuiteNistMappings;
const indexByRule = new Map<string, ScoutsuiteNistMapping>(
  mappings.map(m => [m.RULE, m])
);

/**
 * Get the full mapping for a ScoutSuite rule
 * @param rule - The ScoutSuite rule name
 * @returns The mapping object or undefined if not found
 */
export function getScoutsuiteNistMapping(rule: string): ScoutsuiteNistMapping | undefined {
  return indexByRule.get(rule);
}

/**
 * Get the NIST control ID for a ScoutSuite rule
 * @param rule - The ScoutSuite rule name
 * @returns The NIST control ID or undefined if not found
 */
export function getScoutsuiteNistControl(rule: string): string | undefined {
  const mapping = getScoutsuiteNistMapping(rule);
  return mapping?.['NIST-ID'];
}

/**
 * Get all ScoutSuite rule names
 * @returns Array of all rule names
 */
export function getAllScoutsuiteRules(): string[] {
  return Array.from(indexByRule.keys());
}

/**
 * Check if a ScoutSuite rule exists in the mappings
 * @param rule - The rule name to check
 * @returns True if the rule exists
 */
export function scoutsuiteRuleExists(rule: string): boolean {
  return indexByRule.has(rule);
}

/**
 * Get all ScoutSuite to NIST mappings
 * @returns Array of all mappings
 */
export function getAllScoutsuiteMappings(): ScoutsuiteNistMappings {
  return [...mappings];
}
