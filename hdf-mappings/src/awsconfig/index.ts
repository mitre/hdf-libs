/**
 * Query functions for AWS Config to NIST mappings
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AwsConfigNistMapping, AwsConfigNistMappings } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mappings: AwsConfigNistMappings | null = null;
let indexByIdentifier: Map<string, AwsConfigNistMapping> | null = null;
let indexByRuleName: Map<string, AwsConfigNistMapping> | null = null;

function loadMappings(): void {
  if (mappings === null) {
    const dataPath = join(__dirname, '../data/awsconfig-mappings.json');
    const data = readFileSync(dataPath, 'utf-8');
    mappings = JSON.parse(data) as AwsConfigNistMappings;

    // Build indexes for fast lookups
    indexByIdentifier = new Map();
    indexByRuleName = new Map();
    for (const mapping of mappings) {
      indexByIdentifier.set(mapping.AwsConfigRuleSourceIdentifier, mapping);
      indexByRuleName.set(mapping.AwsConfigRuleName, mapping);
    }
  }
}

/**
 * Get the full mapping for an AWS Config rule by source identifier
 * @param identifier - The AWS Config rule source identifier
 * @returns The mapping object or undefined if not found
 */
export function getAwsConfigNistMappingByIdentifier(
  identifier: string
): AwsConfigNistMapping | undefined {
  loadMappings();
  return indexByIdentifier!.get(identifier);
}

/**
 * Get the full mapping for an AWS Config rule by rule name
 * @param ruleName - The AWS Config rule name
 * @returns The mapping object or undefined if not found
 */
export function getAwsConfigNistMappingByName(
  ruleName: string
): AwsConfigNistMapping | undefined {
  loadMappings();
  return indexByRuleName!.get(ruleName);
}

/**
 * Get the NIST control ID for an AWS Config rule by source identifier
 * @param identifier - The AWS Config rule source identifier
 * @returns The NIST control ID or undefined if not found
 */
export function getAwsConfigNistControlByIdentifier(identifier: string): string | undefined {
  const mapping = getAwsConfigNistMappingByIdentifier(identifier);
  return mapping?.['NIST-ID'];
}

/**
 * Get the NIST control ID for an AWS Config rule by rule name
 * @param ruleName - The AWS Config rule name
 * @returns The NIST control ID or undefined if not found
 */
export function getAwsConfigNistControlByName(ruleName: string): string | undefined {
  const mapping = getAwsConfigNistMappingByName(ruleName);
  return mapping?.['NIST-ID'];
}

/**
 * Get all AWS Config rule source identifiers
 * @returns Array of all rule source identifiers
 */
export function getAllAwsConfigIdentifiers(): string[] {
  loadMappings();
  return Array.from(indexByIdentifier!.keys());
}

/**
 * Get all AWS Config rule names
 * @returns Array of all rule names
 */
export function getAllAwsConfigRuleNames(): string[] {
  loadMappings();
  return Array.from(indexByRuleName!.keys());
}

/**
 * Check if an AWS Config rule exists by source identifier
 * @param identifier - The rule source identifier to check
 * @returns True if the rule exists
 */
export function awsConfigIdentifierExists(identifier: string): boolean {
  loadMappings();
  return indexByIdentifier!.has(identifier);
}

/**
 * Check if an AWS Config rule exists by rule name
 * @param ruleName - The rule name to check
 * @returns True if the rule exists
 */
export function awsConfigRuleNameExists(ruleName: string): boolean {
  loadMappings();
  return indexByRuleName!.has(ruleName);
}

/**
 * Get all AWS Config to NIST mappings
 * @returns Array of all mappings
 */
export function getAllAwsConfigMappings(): AwsConfigNistMappings {
  loadMappings();
  return [...mappings!];
}
