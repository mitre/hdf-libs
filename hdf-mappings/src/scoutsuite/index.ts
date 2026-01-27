/**
 * Query functions for ScoutSuite to NIST mappings
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScoutsuiteNistMapping, ScoutsuiteNistMappings } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mappings: ScoutsuiteNistMappings | null = null;
let indexByRule: Map<string, ScoutsuiteNistMapping> | null = null;

function loadMappings(): void {
  if (mappings === null) {
    const dataPath = join(__dirname, '../data/scoutsuite-nist-mappings.json');
    const data = readFileSync(dataPath, 'utf-8');
    mappings = JSON.parse(data) as ScoutsuiteNistMappings;

    // Build index for fast lookups
    indexByRule = new Map();
    for (const mapping of mappings) {
      indexByRule.set(mapping.RULE, mapping);
    }
  }
}

/**
 * Get the full mapping for a ScoutSuite rule
 * @param rule - The ScoutSuite rule name
 * @returns The mapping object or undefined if not found
 */
export function getScoutsuiteNistMapping(rule: string): ScoutsuiteNistMapping | undefined {
  loadMappings();
  return indexByRule!.get(rule);
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
  loadMappings();
  return Array.from(indexByRule!.keys());
}

/**
 * Check if a ScoutSuite rule exists in the mappings
 * @param rule - The rule name to check
 * @returns True if the rule exists
 */
export function scoutsuiteRuleExists(rule: string): boolean {
  loadMappings();
  return indexByRule!.has(rule);
}

/**
 * Get all ScoutSuite to NIST mappings
 * @returns Array of all mappings
 */
export function getAllScoutsuiteMappings(): ScoutsuiteNistMappings {
  loadMappings();
  return [...mappings!];
}
